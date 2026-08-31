import com.agentclientprotocol.protocol.JsonRpcException;
import decompengine.acp.AcpAgentHarness;
import decompengine.acp.AcpEnvironmentProvenance;
import decompengine.acp.AcpExecutionCleanupDisposition;
import decompengine.acp.AcpExecutionLifecyclePhase;
import decompengine.acp.AcpHarnessFactory;
import decompengine.acp.AcpHarnessKind;
import decompengine.acp.AcpHarnessSelection;
import decompengine.acp.AcpInvocationEvidenceSnapshot;
import decompengine.acp.AcpSandboxLaunchPurpose;
import decompengine.agent.AgentAccessPolicy;
import decompengine.agent.AgentCancellation;
import decompengine.agent.AgentContextInput;
import decompengine.agent.AgentExecutionEvent;
import decompengine.agent.AgentExecutionException;
import decompengine.agent.AgentExecutionLimits;
import decompengine.agent.AgentExecutionOutcome;
import decompengine.agent.AgentExecutionReceipt;
import decompengine.agent.AgentExecutionRequest;
import decompengine.agent.AgentFailure;
import decompengine.agent.AgentFailureKind;
import decompengine.agent.AgentOperation;
import decompengine.agent.AgentPathRule;
import decompengine.agent.AgentWorkspaceRoot;
import java.nio.ByteBuffer;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import kotlin.Unit;

/**
 * Proves the credential-free codex-acp authentication boundary through the production ACP harness.
 *
 * The probe deliberately grants no filesystem, terminal, permission, network, credential, prompt,
 * or oracle authority. A successful qualification is the expected typed authentication failure
 * after stable-v1 initialize and an attempted session/new, followed by verified cleanup.
 */
public final class AcpCompatibilityAuthenticationProbe {
    private static final String AGENT_ID = "codex-acp";
    private static final String AGENT_VERSION = "0.16.0";
    private static final String IMPLEMENTATION_ID = AGENT_ID + "-" + AGENT_VERSION;
    private static final String ARCHIVE_URL =
        "https://github.com/zed-industries/codex-acp/releases/download/v0.16.0/" +
            "codex-acp-0.16.0-x86_64-unknown-linux-gnu.tar.gz";
    private static final String ARCHIVE_SHA256 =
        "0a9ad6c31ec9b2b87dccb7e9da3faf5d387e74470d24dbced75a160ed7b22d06";
    private static final String EXECUTABLE_ENTRY = "codex-acp";
    private static final String EXECUTABLE_SHA256 =
        "23a9f2af247fc61aa9a895d5ee91a62a35d05a883bddc2c85d1dc6b2be697087";
    private static final String RESOURCE_ENTRY = "codex-resources/bwrap";
    private static final String RESOURCE_SHA256 =
        "5a5104807cfbe9b509d0b9fa1c46054ff48dbed5393f30d261b34263ebf0e3fe";
    private static final int AUTH_REQUIRED = -32_000;

    private AcpCompatibilityAuthenticationProbe() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 4) {
            throw new IllegalArgumentException(
                "usage: AcpCompatibilityAuthenticationProbe <config> <evidence> " +
                    "<empty-workspace> <executable-manifest-sha256>"
            );
        }
        var config = requireExistingFile("ACP compatibility config", Path.of(arguments[0]));
        var evidence = requireNewOutput(Path.of(arguments[1]));
        var workspace = requireEmptyWorkspace(Path.of(arguments[2]));
        var initialWorkspace = captureWorkspace(workspace);
        var executableManifestSha256 = requireSha256(
            "executable manifest SHA-256",
            arguments[3]
        );
        var startedAt = Instant.now();
        var startedNanos = System.nanoTime();
        AcpHarnessSelection selection = null;
        AgentExecutionReceipt receipt = null;
        try {
            selection = AcpHarnessFactory.INSTANCE.fromEnvironment(
                Map.of("ACP_CONFIG_FILE", config.toString())
            );
            requireExpectedSelection(selection, executableManifestSha256);

            var events = Collections.synchronizedList(new ArrayList<AgentExecutionEvent>());
            var request = new AgentExecutionRequest(
                "Verify the configured ACP authentication boundary without workspace authority",
                List.of(new AgentWorkspaceRoot("compatibility", workspace)),
                List.<AgentContextInput>of(),
                new AgentAccessPolicy(List.<AgentPathRule>of(), Set.<AgentOperation>of()),
                new AgentExecutionLimits(
                    Duration.ofSeconds(40),
                    Duration.ofSeconds(10),
                    1,
                    1,
                    2L * 1024 * 1024,
                    null,
                    null
                ),
                AgentCancellation.Companion.getNONE()
            );
            var harness = (AcpAgentHarness) selection.createHarness();
            receipt = harness.executeReceipt(request, event -> {
                events.add(event);
                return Unit.INSTANCE;
            });

            var failed = requireAuthenticationFailure(receipt);
            var rpcFailure = requireTypedRpcFailure(receipt, failed.getFailure());
            var invocation = requireInvocationEvidence(receipt, selection);
            requireExpectedNegotiation(invocation);
            requireExpectedContainment(invocation);
            requireCondition(events.isEmpty(), "authentication probe unexpectedly emitted events");
            var finalWorkspace = captureWorkspace(workspace);
            requireCondition(
                initialWorkspace.equals(finalWorkspace),
                "authentication probe changed its empty workspace"
            );

            var document = baseEvidence(
                "passed",
                executableManifestSha256,
                startedAt,
                startedNanos
            );
            document.put("scope", successfulScope());
            document.put("factoryProvenance", factoryEvidence(selection));
            document.put("requestBinding", object(
                "contractVersion", receipt.getRequestBinding().getContractVersion(),
                "requestSha256", receipt.getRequestBinding().getRequestSha256(),
                "accessPolicySha256", receipt.getRequestBinding().getAccessPolicySha256()
            ));
            document.put("negotiated", negotiatedEvidence(invocation));
            document.put("terminalOutcome", object(
                "kind", "authentication",
                "retryable", failed.getFailure().getRetryable(),
                "sessionPresent", failed.getFailure().getSession() != null,
                "rpcCode", rpcFailure.getCode(),
                "rpcDataPresent", rpcFailure.getData() != null
            ));
            document.put("invocation", invocationEvidence(invocation));
            document.put("process", processEvidence(invocation));
            document.put("sandbox", sandboxEvidence(invocation));
            document.put("workspace", object(
                "initiallyEmpty", true,
                "unchanged", true,
                "finalEntryCount", 0
            ));
            writeEvidence(evidence, document);
            System.out.println(
                "codex-acp-0.16.0:stable-v1:initialized:authentication-required:cleanup-verified"
            );
        } catch (Throwable failure) {
            var document = baseEvidence(
                "failed",
                executableManifestSha256,
                startedAt,
                startedNanos
            );
            var workspaceUnchanged = workspaceStillMatches(workspace, initialWorkspace);
            document.put("scope", observedScope(receipt, workspaceUnchanged));
            if (selection != null) {
                document.put("factoryProvenance", factoryEvidence(selection));
            }
            if (receipt != null &&
                receipt.getProviderEvidence() instanceof AcpInvocationEvidenceSnapshot invocation) {
                document.put("invocation", invocationEvidence(invocation));
                if (invocation.getNegotiatedAgent() != null) {
                    document.put("negotiated", negotiatedEvidence(invocation));
                }
                if (invocation.getDiagnostics() != null) {
                    document.put("process", processEvidence(invocation));
                }
                if (invocation.getSandboxEvidence() != null) {
                    document.put("sandbox", sandboxEvidence(invocation));
                }
            }
            document.put("workspace", object(
                "initiallyEmpty", true,
                "unchanged", workspaceUnchanged,
                "finalEntryCount", countEntries(workspace)
            ));
            document.put("failure", object(
                "type", failure.getClass().getName(),
                "message", boundedMessage(failure)
            ));
            writeEvidence(evidence, document);
            if (failure instanceof Exception exception) {
                throw exception;
            }
            throw new RuntimeException("ACP authentication-boundary qualification failed", failure);
        }
    }

    private static void requireExpectedSelection(
        AcpHarnessSelection selection,
        String executableManifestSha256
    ) throws Exception {
        requireCondition(
            selection.getKind() == AcpHarnessKind.ACP,
            "authentication qualification selected a non-ACP harness"
        );
        var provenance = selection.getProvenance();
        requireCondition(
            provenance.getHarness().equals("acp") &&
                provenance.getImplementationId().equals(IMPLEMENTATION_ID) &&
                provenance.getAcpProtocolVersion() != null &&
                provenance.getAcpProtocolVersion() == 1 &&
                provenance.getAcpSdkVersion().equals("0.30.1") &&
                !provenance.getDeprecated(),
            "authentication qualification has unexpected factory provenance"
        );
        var configuration = selection.getConfiguration();
        requireCondition(configuration != null, "authentication qualification omitted ACP configuration");
        requireCondition(
            configuration.getImplementationId().equals(IMPLEMENTATION_ID) &&
                configuration.getArguments().isEmpty() &&
                !configuration.getInheritParentEnvironment() &&
                configuration.getRequiredAgentCapabilities().isEmpty() &&
                configuration.getTerminalPolicy() == null &&
                executableManifestSha256.equals(
                    configuration.getExpectedExecutableManifestSha256()
                ),
            "authentication qualification target does not match its provisioning"
        );
        requireCondition(
            configuration.getExecutable().getFileName().toString().equals(EXECUTABLE_ENTRY) &&
                fileSha256(configuration.getExecutable()).equals(EXECUTABLE_SHA256),
            "authentication qualification executable does not match the pinned release"
        );
        requireCondition(
            configuration.getEnvironment().keySet().equals(Set.of(
                "HOME",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_CACHE_HOME"
            )) &&
                configuration.getEnvironment().values().stream().allMatch(
                    value -> value.getProvenance() == AcpEnvironmentProvenance.PUBLIC
                ),
            "authentication qualification environment is not the exact public private-home set"
        );
        var sandbox = configuration.getSandboxBoundary();
        requireCondition(sandbox != null, "authentication qualification omitted production containment");
        var archiveRoot = configuration.getExecutable().getParent();
        var bundledResource = archiveRoot.resolve(RESOURCE_ENTRY).normalize();
        requireCondition(
            bundledResource.startsWith(archiveRoot) &&
                Files.isRegularFile(bundledResource, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(bundledResource) &&
                fileSha256(bundledResource).equals(RESOURCE_SHA256),
            "authentication qualification bundled resource does not match the pinned archive"
        );
        requireCondition(
            sandbox.getAgentRuntimeMounts().stream().noneMatch(
                mount -> mount.getSource().equals(bundledResource)
            ),
            "authentication qualification must not grant the unused bundled sandbox helper"
        );
    }

    private static AgentExecutionOutcome.Failed requireAuthenticationFailure(
        AgentExecutionReceipt receipt
    ) {
        requireCondition(
            receipt.getOutcome() instanceof AgentExecutionOutcome.Failed,
            "credential-free session creation unexpectedly returned a result"
        );
        var failed = (AgentExecutionOutcome.Failed) receipt.getOutcome();
        var failure = failed.getFailure();
        requireCondition(
            failure.getKind() == AgentFailureKind.AUTHENTICATION &&
                failure.getRetryable() &&
                failure.getSession() == null &&
                failure.getDetails().equals(Map.of("rpcCode", Integer.toString(AUTH_REQUIRED))),
            "credential-free session creation did not return the exact typed authentication failure"
        );
        return failed;
    }

    private static JsonRpcException requireTypedRpcFailure(
        AgentExecutionReceipt receipt,
        AgentFailure expectedFailure
    ) {
        try {
            receipt.requireResult();
            throw new IllegalStateException("failed authentication receipt unexpectedly returned a result");
        } catch (AgentExecutionException compatibility) {
            requireCondition(
                compatibility.getReceipt() == receipt &&
                    compatibility.getCause() instanceof AgentExecutionException,
                "authentication receipt did not preserve its typed mapped failure"
            );
            var mapped = (AgentExecutionException) compatibility.getCause();
            requireCondition(
                mapped.getFailure() == expectedFailure && mapped.getCause() instanceof JsonRpcException,
                "authentication receipt did not preserve its typed ACP JSON-RPC failure"
            );
            var rpcFailure = (JsonRpcException) mapped.getCause();
            requireCondition(
                rpcFailure.getCode() == AUTH_REQUIRED && rpcFailure.getData() == null,
                "ACP authentication failure did not use -32000 with absent data"
            );
            return rpcFailure;
        }
    }

    private static AcpInvocationEvidenceSnapshot requireInvocationEvidence(
        AgentExecutionReceipt receipt,
        AcpHarnessSelection selection
    ) {
        requireCondition(
            receipt.getProviderEvidence() instanceof AcpInvocationEvidenceSnapshot,
            "authentication receipt omitted ACP invocation evidence"
        );
        var invocation = (AcpInvocationEvidenceSnapshot) receipt.getProviderEvidence();
        requireCondition(
            invocation.getProviderId().equals("acp") &&
                invocation.getSchemaVersion() == 2 &&
                invocation.getFactoryProvenance().equals(selection.getProvenance()) &&
                invocation.getPhaseReached() == AcpExecutionLifecyclePhase.INITIALIZED &&
                invocation.getCleanupDisposition() == AcpExecutionCleanupDisposition.VERIFIED &&
                invocation.getWirePromptSha256() == null &&
                invocation.getCompleteExecutionEvidence() == null,
            "authentication receipt crossed an unexpected ACP lifecycle boundary"
        );
        requireCondition(
            invocation.getFilesystemAudit().isEmpty() &&
                invocation.getTerminalAudit().isEmpty() &&
                invocation.getPermissionAudit().isEmpty() &&
                invocation.getCompleteness().getFilesystemAuditComplete() &&
                invocation.getCompleteness().getTerminalAuditComplete() &&
                invocation.getCompleteness().getPermissionAuditComplete() &&
                invocation.getCompleteness().getAllPolicyAuditsComplete(),
            "authentication receipt contains incomplete or non-empty policy audits"
        );
        return invocation;
    }

    private static void requireExpectedNegotiation(AcpInvocationEvidenceSnapshot invocation) {
        var negotiated = invocation.getNegotiatedAgent();
        requireCondition(negotiated != null, "authentication receipt omitted negotiated identity");
        var capabilities = negotiated.getCapabilities();
        requireCondition(
            negotiated.getProtocolVersion() == 1 &&
                negotiated.getImplementationName().equals(AGENT_ID) &&
                negotiated.getImplementationVersion().equals(AGENT_VERSION) &&
                Objects.equals(negotiated.getImplementationTitle(), "Codex") &&
                capabilities.getLoadSession() &&
                capabilities.getPromptImage() &&
                !capabilities.getPromptAudio() &&
                capabilities.getPromptEmbeddedContext() &&
                capabilities.getMcpHttp() &&
                !capabilities.getMcpSse() &&
                !capabilities.getSessionAdditionalDirectories(),
            "authentication receipt negotiated unexpected codex-acp identity or capabilities"
        );
    }

    private static void requireExpectedContainment(AcpInvocationEvidenceSnapshot invocation) {
        var diagnostics = invocation.getDiagnostics();
        requireCondition(diagnostics != null, "authentication receipt omitted process diagnostics");
        requireCondition(
            diagnostics.getNetworkIsolated() &&
                diagnostics.getSandboxCleanupVerified() &&
                diagnostics.getRemainingProcessIds().isEmpty() &&
                !diagnostics.getOutputLimitExceeded(),
            "authentication receipt did not prove bounded process cleanup"
        );
        var sandbox = invocation.getSandboxEvidence();
        requireCondition(sandbox != null, "authentication receipt omitted sandbox evidence");
        requireCondition(
            sandbox.getNetworkIsolated() &&
                sandbox.getOuterAgentContained() &&
                sandbox.getCgroupV2PidsLimited() &&
                sandbox.getCgroupV2MemoryLimited() &&
                sandbox.getCgroupV2CpuLimited() &&
                sandbox.getNestedUserNamespacesDisabled() &&
                sandbox.getNewSession() &&
                sandbox.getDieWithParent() &&
                sandbox.getTerminalLimits() == null &&
                sandbox.getPolicySha256() == null &&
                sandbox.getTerminalAudit().isEmpty() &&
                sandbox.getLaunches().size() == 1 &&
                sandbox.getLaunches().get(0).getPurpose() == AcpSandboxLaunchPurpose.OUTER_AGENT &&
                sandbox.getOuterProcessOutput() != null &&
                !sandbox.getOuterProcessOutput().getLimitExceeded(),
            "authentication receipt did not prove the exact no-terminal outer containment"
        );
    }

    private static LinkedHashMap<String, Object> baseEvidence(
        String status,
        String executableManifestSha256,
        Instant startedAt,
        long startedNanos
    ) {
        var result = new LinkedHashMap<String, Object>();
        result.put("schema", "decomp-engine-acp-compatibility-authentication-boundary");
        result.put("schemaVersion", 1);
        result.put("status", status);
        result.put("case", "credential-free-session-authentication-boundary");
        result.put("agentTarget", object(
            "id", AGENT_ID,
            "version", AGENT_VERSION,
            "archiveUrl", ARCHIVE_URL,
            "archiveSha256", ARCHIVE_SHA256,
            "archiveEntries", List.of(EXECUTABLE_ENTRY, RESOURCE_ENTRY),
            "executableSha256", EXECUTABLE_SHA256,
            "bundledResourceSha256", RESOURCE_SHA256,
            "bundledResourceMounted", false,
            "executableManifestSha256", executableManifestSha256,
            "argv", List.of(EXECUTABLE_ENTRY)
        ));
        result.put("client", object(
            "implementation", "decomp_engine",
            "implementationVersion", "0.1.0",
            "protocolVersion", 1,
            "sdk", "com.agentclientprotocol:acp:0.30.1"
        ));
        result.put("environmentAssumptions", List.of(
            "Linux x86-64",
            "unprivileged user namespaces and bubblewrap",
            "live same-UID user-systemd manager with cgroup v2 authority",
            "private empty HOME and XDG state",
            "credential-free authentication boundary only; no external model service"
        ));
        result.put("startedAt", startedAt.toString());
        result.put("finishedAt", Instant.now().toString());
        result.put("elapsedMillis", Math.max(0, (System.nanoTime() - startedNanos) / 1_000_000));
        return result;
    }

    private static Map<String, Object> successfulScope() {
        return object(
            "initializeRequired", true,
            "initializeCompleted", true,
            "sessionCreationAttempted", true,
            "sessionCreated", false,
            "modelPromptSent", false,
            "workspaceFilesystemAuthorityGranted", false,
            "workspaceFilesystemEdits", false,
            "terminalAuthorityGranted", false,
            "permissionAuthorityGranted", false,
            "credentialsForwarded", false,
            "outerNetworkEnabled", false,
            "oracleAccessGranted", false
        );
    }

    private static Map<String, Object> observedScope(
        AgentExecutionReceipt receipt,
        boolean workspaceUnchanged
    ) {
        var invocation = receipt != null &&
            receipt.getProviderEvidence() instanceof AcpInvocationEvidenceSnapshot evidence
                ? evidence
                : null;
        var phase = invocation == null
            ? AcpExecutionLifecyclePhase.REQUEST_BOUND
            : invocation.getPhaseReached();
        var initialized = invocation != null &&
            invocation.getNegotiatedAgent() != null &&
            phase.ordinal() >= AcpExecutionLifecyclePhase.INITIALIZED.ordinal();
        var authenticationFailure = receipt != null &&
            receipt.getOutcome() instanceof AgentExecutionOutcome.Failed failed &&
            failed.getFailure().getKind() == AgentFailureKind.AUTHENTICATION;
        return object(
            "initializeRequired", true,
            "initializeCompleted", initialized,
            "sessionCreationAttempted", initialized && authenticationFailure,
            "sessionCreated", phase.ordinal() >= AcpExecutionLifecyclePhase.SESSION_CREATED.ordinal(),
            "modelPromptSent", phase.ordinal() >= AcpExecutionLifecyclePhase.PROMPT_DISPATCHED.ordinal(),
            "workspaceFilesystemAuthorityGranted", false,
            "workspaceFilesystemEdits", !workspaceUnchanged,
            "terminalAuthorityGranted", false,
            "permissionAuthorityGranted", false,
            "credentialsForwarded", false,
            "outerNetworkEnabled", false,
            "oracleAccessGranted", false
        );
    }

    private static Map<String, Object> factoryEvidence(AcpHarnessSelection selection) {
        var provenance = selection.getProvenance();
        return object(
            "harness", provenance.getHarness(),
            "implementationId", provenance.getImplementationId(),
            "agentExecutionContractVersion", provenance.getAgentExecutionContractVersion(),
            "acpProtocolVersion", provenance.getAcpProtocolVersion(),
            "acpSdkVersion", provenance.getAcpSdkVersion(),
            "configurationSha256", provenance.getConfigurationSha256(),
            "deprecated", provenance.getDeprecated()
        );
    }

    private static Map<String, Object> negotiatedEvidence(AcpInvocationEvidenceSnapshot invocation) {
        var negotiated = invocation.getNegotiatedAgent();
        if (negotiated == null) {
            throw new IllegalStateException("ACP invocation has no negotiated identity");
        }
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

    private static Map<String, Object> invocationEvidence(AcpInvocationEvidenceSnapshot invocation) {
        return object(
            "providerId", invocation.getProviderId(),
            "providerSchemaVersion", invocation.getSchemaVersion(),
            "phaseReached", invocation.getPhaseReached().name(),
            "cleanupDisposition", invocation.getCleanupDisposition().name(),
            "sessionCreated",
                invocation.getPhaseReached().ordinal() >=
                    AcpExecutionLifecyclePhase.SESSION_CREATED.ordinal(),
            "wirePromptSha256", invocation.getWirePromptSha256(),
            "completeExecutionEvidencePresent", invocation.getCompleteExecutionEvidence() != null,
            "filesystemAuditRecords", invocation.getFilesystemAudit().size(),
            "terminalAuditRecords", invocation.getTerminalAudit().size(),
            "permissionAuditRecords", invocation.getPermissionAudit().size(),
            "filesystemAuditComplete", invocation.getCompleteness().getFilesystemAuditComplete(),
            "terminalAuditComplete", invocation.getCompleteness().getTerminalAuditComplete(),
            "permissionAuditComplete", invocation.getCompleteness().getPermissionAuditComplete()
        );
    }

    private static Map<String, Object> processEvidence(AcpInvocationEvidenceSnapshot invocation) {
        var diagnostics = invocation.getDiagnostics();
        if (diagnostics == null) {
            throw new IllegalStateException("ACP invocation has no process diagnostics");
        }
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
            "outputLimitExceeded", diagnostics.getOutputLimitExceeded(),
            "stderrTruncated", diagnostics.getStderrTruncated()
        );
    }

    private static Map<String, Object> sandboxEvidence(AcpInvocationEvidenceSnapshot invocation) {
        var sandbox = invocation.getSandboxEvidence();
        if (sandbox == null) {
            throw new IllegalStateException("ACP invocation has no sandbox evidence");
        }
        var limits = sandbox.getOuterAgentLimits();
        var closure = sandbox.getRuntimeClosureLimits();
        var output = sandbox.getOuterProcessOutput();
        return object(
            "provider", sandbox.getProvider(),
            "providerVersion", sandbox.getProviderVersion(),
            "providerExecutableSha256", sandbox.getProviderExecutableSha256(),
            "resourceLimiterSha256", sandbox.getResourceLimiterSha256(),
            "scopeSupervisorSha256", sandbox.getScopeSupervisorSha256(),
            "scopeInspectorSha256", sandbox.getScopeInspectorSha256(),
            "environmentFdOpenerSha256", sandbox.getEnvironmentFdOpenerSha256(),
            "evidenceSha256", sandbox.getEvidenceSha256(),
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
            "dieWithParent", sandbox.getDieWithParent(),
            "policySha256", sandbox.getPolicySha256(),
            "terminalLimitsPresent", sandbox.getTerminalLimits() != null,
            "launchCount", sandbox.getLaunches().size(),
            "terminalLaunchCount", sandbox.getLaunches().stream()
                .filter(launch -> launch.getPurpose() == AcpSandboxLaunchPurpose.TERMINAL)
                .count(),
            "authorityRecordCount", sandbox.getAuthorities().size(),
            "output", output == null ? null : object(
                "maximumBytes", output.getMaximumBytes(),
                "observedBytes", output.getObservedBytes(),
                "limitExceeded", output.getLimitExceeded()
            )
        );
    }

    private static Path requireExistingFile(String label, Path configured) throws Exception {
        var normalized = configured.toAbsolutePath().normalize();
        if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(normalized)) {
            throw new IllegalArgumentException(label + " must be a real file");
        }
        return normalized;
    }

    private static Path requireNewOutput(Path configured) {
        var normalized = configured.toAbsolutePath().normalize();
        var parent = normalized.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(parent) || Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException(
                "ACP compatibility evidence output must be a new file in a real directory"
            );
        }
        return normalized;
    }

    private static Path requireEmptyWorkspace(Path configured) throws Exception {
        var normalized = configured.toAbsolutePath().normalize();
        var real = normalized.toRealPath();
        if (!normalized.equals(real) || !Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(real) || countEntries(real) != 0) {
            throw new IllegalArgumentException(
                "ACP authentication workspace must be a canonical empty directory"
            );
        }
        return real;
    }

    private static WorkspaceState captureWorkspace(Path workspace) throws Exception {
        var attributes = Files.readAttributes(
            workspace,
            BasicFileAttributes.class,
            LinkOption.NOFOLLOW_LINKS
        );
        requireCondition(attributes.isDirectory(), "ACP authentication workspace is no longer a directory");
        requireCondition(countEntries(workspace) == 0, "ACP authentication workspace is no longer empty");
        return new WorkspaceState(
            attributes.fileKey(),
            attributes.lastModifiedTime(),
            attributes.size()
        );
    }

    private static boolean workspaceStillMatches(Path workspace, WorkspaceState initial) {
        try {
            return captureWorkspace(workspace).equals(initial);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static int countEntries(Path directory) {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            var count = 0;
            for (var ignored : entries) {
                count = Math.addExact(count, 1);
            }
            return count;
        } catch (Exception ignored) {
            return -1;
        }
    }

    private static String requireSha256(String label, String value) {
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(label + " must be lowercase SHA-256");
        }
        return value;
    }

    private static String fileSha256(Path path) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            var buffer = new byte[8192];
            while (true) {
                var count = input.read(buffer);
                if (count < 0) {
                    break;
                }
                digest.update(buffer, 0, count);
            }
        }
        var output = new StringBuilder(64);
        for (var value : digest.digest()) {
            output.append(String.format("%02x", value));
        }
        return output.toString();
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

    private static void requireCondition(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
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

    private record WorkspaceState(Object fileKey, FileTime lastModifiedTime, long size) {}
}

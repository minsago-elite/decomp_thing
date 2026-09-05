package decompengine.repair;

import decompengine.validation.ProcessInput;
import decompengine.validation.ProcessOutput;
import decompengine.validation.BehaviorCaseResult;
import decompengine.validation.BehaviorComparisonReport;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Caller-visible lifetime for the vetted repair workflow.
 *
 * <p>The loop and every present/future worker, lock, and transport resource remain private session
 * state. Closing the session is idempotent and prevents subsequent operations.</p>
 */
public final class SecureRepairSession implements AutoCloseable {
    private final TraceGuidedRepairLoop loop;
    private final String harnessProvenance;
    private boolean closed;

    SecureRepairSession(TraceGuidedRepairLoop loop, String harnessProvenance) {
        this.loop = Objects.requireNonNull(loop, "loop");
        this.harnessProvenance = Objects.requireNonNull(harnessProvenance, "harnessProvenance");
    }

    /** Stable non-secret descriptor of the single harness selection made by the Java gate. */
    public String getHarnessProvenance() {
        return harnessProvenance;
    }

    public synchronized RepairIteration repairCompileError(
        Path projectDirectory,
        CompileFailure failure,
        List<ProcessInput> regressionInputs
    ) {
        requireOpen();
        CompileFailure copiedFailure = new CompileFailure(
            List.copyOf(Objects.requireNonNull(failure, "failure").getCommand()),
            failure.getExitCode(),
            failure.getStdout(),
            failure.getStderr()
        );
        return copyIteration(loop.repairCompileError(
            Objects.requireNonNull(projectDirectory, "projectDirectory"),
            copiedFailure,
            copyInputs(regressionInputs)
        ));
    }

    public synchronized RepairIteration repairBehaviorMismatch(
        Path projectDirectory,
        Path originalBinary,
        Path rebuiltBinary,
        List<ProcessInput> inputs,
        Path reportsDirectory
    ) {
        requireOpen();
        return copyIteration(loop.repairBehaviorMismatch(
            Objects.requireNonNull(projectDirectory, "projectDirectory"),
            Objects.requireNonNull(originalBinary, "originalBinary"),
            Objects.requireNonNull(rebuiltBinary, "rebuiltBinary"),
            copyInputs(inputs),
            Objects.requireNonNull(reportsDirectory, "reportsDirectory")
        ));
    }

    public synchronized RepairRunResult repairUntilValid(
        Path projectDirectory,
        Path originalBinary,
        List<ProcessInput> inputs,
        Path reportsDirectory,
        int maximumIterations
    ) {
        requireOpen();
        return copyRunResult(loop.repairUntilValid(
            Objects.requireNonNull(projectDirectory, "projectDirectory"),
            Objects.requireNonNull(originalBinary, "originalBinary"),
            copyInputs(inputs),
            Objects.requireNonNull(reportsDirectory, "reportsDirectory"),
            maximumIterations
        ));
    }

    /** Versioned whole-run result, including provisional/exhausted/non-release outcomes. */
    public synchronized RepairRunOutcome runRepair(
        Path projectDirectory, Path originalBinary, List<ProcessInput> inputs,
        Path reportsDirectory, int maximumIterations
    ) {
        requireOpen();
        RepairRunOutcome result = loop.runRepair(Objects.requireNonNull(projectDirectory),
            Objects.requireNonNull(originalBinary), copyInputs(inputs), Objects.requireNonNull(reportsDirectory), maximumIterations);
        ArrayList<RepairIteration> iterations = new ArrayList<>(result.getIterations().size());
        for (RepairIteration iteration : result.getIterations()) iterations.add(copyIteration(iteration));
        return new RepairRunOutcome(List.copyOf(iterations),
            result.getValidation() == null ? null : copyReport(result.getValidation()), result.getRunState());
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        loop.close();
    }

    private void requireOpen() {
        if (closed) throw new IllegalStateException("secure repair session is closed");
    }

    private static List<ProcessInput> copyInputs(List<ProcessInput> inputs) {
        Objects.requireNonNull(inputs, "inputs");
        ArrayList<ProcessInput> copied = new ArrayList<>(inputs.size());
        for (ProcessInput input : inputs) {
            Objects.requireNonNull(input, "regression input");
            copied.add(new ProcessInput(input.getId(), List.copyOf(input.getArgs()), input.getStdin().clone()));
        }
        return List.copyOf(copied);
    }

    private static RepairIteration copyIteration(RepairIteration iteration) {
        ArrayList<RepairPatch> patches = new ArrayList<>(iteration.getPatches().size());
        for (RepairPatch patch : iteration.getPatches()) {
            patches.add(new RepairPatch(patch.getRelativePath(), patch.getReplacementBytes()));
        }
        RepairEvidence before = iteration.getBefore() == null ? null : new RepairEvidence(
            iteration.getBefore().getKind(),
            iteration.getBefore().getSummary(),
            iteration.getBefore().getArtifactPath()
        );
        RepairEvidence after = iteration.getAfter() == null ? null : new RepairEvidence(
            iteration.getAfter().getKind(),
            iteration.getAfter().getSummary(),
            iteration.getAfter().getArtifactPath()
        );
        return new RepairIteration(
            iteration.getIndex(),
            iteration.getFailureKind(),
            iteration.getPrompt(),
            iteration.getSummary(),
            List.copyOf(patches),
            List.copyOf(iteration.getRetainedRegressionIds()),
            before,
            after,
            iteration.getSucceeded(),
            iteration.getAgentInvocation() == null ? null : new RepairAgentInvocationBinding(
                iteration.getAgentInvocation().getReceiptPath(),
                iteration.getAgentInvocation().getReceiptSha256(),
                iteration.getAgentInvocation().getReceiptSchemaVersion(),
                iteration.getAgentInvocation().getRequestSha256(),
                iteration.getAgentInvocation().getResultChangesSha256(),
                iteration.getAgentInvocation().getTerminalOutcome(),
                iteration.getAgentInvocation().getReceiptReleaseComplete(),
                iteration.getAgentInvocation().getAssessmentStatus()
            ),
            iteration.getPublicationMode(),
            iteration.getDisposition(),
            iteration.getRevisionId(),
            iteration.getParentRevisionId(),
            iteration.getRunId()
        );
    }

    private static RepairRunResult copyRunResult(RepairRunResult result) {
        ArrayList<RepairIteration> iterations = new ArrayList<>(result.getIterations().size());
        for (RepairIteration iteration : result.getIterations()) iterations.add(copyIteration(iteration));
        return new RepairRunResult(List.copyOf(iterations), copyReport(result.getValidation()), result.getRunState());
    }

    private static BehaviorComparisonReport copyReport(BehaviorComparisonReport report) {
        ArrayList<BehaviorCaseResult> cases = new ArrayList<>(report.getCases().size());
        for (BehaviorCaseResult item : report.getCases()) {
            ProcessOutput original = item.getOriginal();
            ProcessOutput rebuilt = item.getRebuilt();
            cases.add(new BehaviorCaseResult(
                copyInput(item.getInput()),
                new ProcessOutput(
                    original.getExitCode(),
                    original.getStdout().clone(),
                    original.getStderr().clone(),
                    List.copyOf(original.getSandboxCommand()),
                    original.getNetworkIsolated()
                ),
                new ProcessOutput(
                    rebuilt.getExitCode(),
                    rebuilt.getStdout().clone(),
                    rebuilt.getStderr().clone(),
                    List.copyOf(rebuilt.getSandboxCommand()),
                    rebuilt.getNetworkIsolated()
                )
            ));
        }
        return new BehaviorComparisonReport(
            report.getId(),
            report.getOriginalBinary(),
            report.getRebuiltBinary(),
            List.copyOf(cases),
            report.getReportPath()
        );
    }

    private static ProcessInput copyInput(ProcessInput input) {
        return new ProcessInput(input.getId(), List.copyOf(input.getArgs()), input.getStdin().clone());
    }
}

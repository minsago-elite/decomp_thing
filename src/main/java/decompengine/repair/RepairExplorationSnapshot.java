package decompengine.repair;

import decompengine.validation.ProcessInput;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** One-shot, session-issued retained corpus view bound to the graph and original binary. */
public final class RepairExplorationSnapshot {
    private final RepairExplorationSnapshotData binding;

    RepairExplorationSnapshot(RepairExplorationSnapshotData binding) {
        this.binding = Objects.requireNonNull(binding, "binding");
    }

    public List<ProcessInput> getInputs() {
        ArrayList<ProcessInput> copied = new ArrayList<>();
        for (ProcessInput input : binding.getInputs()) {
            copied.add(new ProcessInput(input.getId(), List.copyOf(input.getArgs()), input.getStdin().clone()));
        }
        return List.copyOf(copied);
    }

    public int getFormatVersion() { return binding.getFormatVersion(); }
    public String getProjectPath() { return binding.getProjectPath(); }
    public String getCorpusSha256() { return binding.getCorpusSha256(); }
    public String getGraphSha256() { return binding.getGraphSha256(); }
    public String getProfileSha256() { return binding.getProfileSha256(); }
    public String getIndexSha256() { return binding.getIndexSha256(); }
    public String getHeadId() { return binding.getHeadId(); }
    public String getOriginalBinarySha256() { return binding.getOriginalBinarySha256(); }

    RepairExplorationSnapshotData binding() { return binding; }
}

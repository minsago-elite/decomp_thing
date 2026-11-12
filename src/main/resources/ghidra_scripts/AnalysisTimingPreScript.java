// Observational marker between Ghidra program loading and automatic analysis.
// @category llm_bin_patch

import decompengine.ghidra.BundledGhidraWorker;
import ghidra.app.script.GhidraScript;

public class AnalysisTimingPreScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        BundledGhidraWorker.preAnalysisBoundary();
    }
}

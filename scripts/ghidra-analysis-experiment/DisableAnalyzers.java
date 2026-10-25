// Diagnostic-only: disables the named auto-analysis analyzers before analysis runs.
//@category Diagnostics

import ghidra.app.script.GhidraScript;

public class DisableAnalyzers extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (String argument : getScriptArgs()) {
            for (String name : argument.split(",")) {
                if (name.isBlank()) continue;
                setAnalysisOption(currentProgram, name.trim(), "false");
                println("ANALYZER-EXPERIMENT disabled " + name.trim());
            }
        }
    }
}

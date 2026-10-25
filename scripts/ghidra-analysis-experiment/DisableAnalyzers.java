// Diagnostic-only: disables the named auto-analysis analyzers before analysis runs.
//@category Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import java.util.Set;
import java.util.TreeSet;

public class DisableAnalyzers extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        Set<String> requested = new TreeSet<>();
        for (String argument : getScriptArgs()) {
            for (String value : argument.split(",", -1)) {
                String name = value.trim();
                if (name.isEmpty() || name.length() > 256 || !requested.add(name)
                        || requested.size() > 256) {
                    throw new IllegalArgumentException("invalid or duplicate analyzer option");
                }
                if (!options.contains(name) || options.getType(name) != OptionType.BOOLEAN_TYPE) {
                    throw new IllegalArgumentException("unknown boolean analyzer option: " + name);
                }
            }
        }
        // Ghidra's setAnalysisOption logs invalid names rather than throwing. Validate the
        // complete request first, so one unsupported name cannot produce a partial variant.
        for (String name : requested) {
            monitor.checkCancelled();
            options.setBoolean(name, false);
            if (options.getBoolean(name, true)) {
                throw new IllegalStateException("analyzer option remained enabled: " + name);
            }
            println("ANALYZER-EXPERIMENT disabled " + name);
        }
    }
}

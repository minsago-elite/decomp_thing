import decompengine.ghidra.BundledGhidraWorker;
import ghidra.app.script.GhidraScript;
import java.util.Arrays;
import java.util.Set;

public final class RunBundledExports extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length == 0) throw new IllegalArgumentException("No bundled exporters requested");
        Set<String> exporters = Set.of("ExportProgramModel.java", "ExportRecoveredCallSites.java", "ExportDecompiledC.java");
        for (int index = 0; index < arguments.length;) {
            String name = arguments[index++];
            if (!exporters.contains(name) || index == arguments.length) {
                throw new IllegalArgumentException("Invalid bundled exporter");
            }
            int count = Integer.parseInt(arguments[index++]);
            if (count < 0 || count > 16 || count > arguments.length - index) {
                throw new IllegalArgumentException("Invalid bundled exporter arguments");
            }
            runScript(name, Arrays.copyOfRange(arguments, index, index + count));
            index += count;
        }
        BundledGhidraWorker.exportsCompleted();
    }
}

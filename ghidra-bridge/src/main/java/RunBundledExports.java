import decompengine.ghidra.BundledGhidraWorker;
import ghidra.app.script.GhidraScript;
import java.util.Arrays;
import java.util.Set;

public final class RunBundledExports extends GhidraScript {
    @Override
    protected void run() throws Exception {
        BundledGhidraWorker.diagnosticsGuard();
        String[] arguments = getScriptArgs();
        if (arguments.length == 0) throw new IllegalArgumentException("No bundled exporters requested");
        // Keep the owned analyzer and typed listing collector on distinct exact-name routes.
        Set<String> exporters = Set.of("ExportProgramModel.java", "ExportProgramModelOwned.java",
            "ExportRecoveredCallSites.java", "ExportDecompiledC.java", "ExportNativeCallsV1.class",
            "ExportNativeInterfacesV1.class", "ExportInferredInterfacesV1.class");
        for (int index = 0; index < arguments.length;) {
            String name = arguments[index++];
            if (!exporters.contains(name) || index == arguments.length) {
                throw new IllegalArgumentException("Invalid bundled exporter");
            }
            int count = Integer.parseInt(arguments[index++]);
            if (count < 0 || count > 16 || count > arguments.length - index) {
                throw new IllegalArgumentException("Invalid bundled exporter arguments");
            }
            BundledGhidraWorker.diagnosticsExporter(name);
            try {
                String[] exporterArguments = Arrays.copyOfRange(arguments, index, index + count);
                if (name.equals("ExportNativeCallsV1.class")) {
                    // The nested source-script loader cannot load the pinned compiled collector.
                    ExportNativeCallsV1.collect(currentProgram, monitor, exporterArguments);
                } else if (name.equals("ExportNativeInterfacesV1.class")) {
                    ExportNativeInterfacesV1.collect(currentProgram, monitor, exporterArguments);
                } else if (name.equals("ExportInferredInterfacesV1.class")) {
                    ExportInferredInterfacesV1.collect(currentProgram, monitor, exporterArguments);
                } else {
                    runScript(name, exporterArguments);
                }
            } finally {
                BundledGhidraWorker.diagnosticsGuard();
            }
            index += count;
        }
        BundledGhidraWorker.exportsCompleted();
        BundledGhidraWorker.diagnosticsFinalization();
    }
}

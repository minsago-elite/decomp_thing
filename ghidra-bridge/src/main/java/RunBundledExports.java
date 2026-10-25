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
        // At most six fixed phase records for the prevalidated interface route. This does
        // not replace or reset the collector's own lifetime, which starts before hashing.
        boolean interfacePhases = arguments.length == 27 &&
            arguments[14].equals("ExportInferredInterfacesV1.class");
        Set<String> exporters = Set.of("ExportProgramModel.java", "ExportRecoveredCallSites.java", "ExportDecompiledC.java", "ExportNativeCallsV1.class", "ExportNativeInterfacesV1.class", "ExportInferredInterfacesV1.class");
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
            long phaseStarted = System.nanoTime();
            boolean phaseComplete = false;
            if (interfacePhases) interfacePhase(name, "started", 0L);
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
                phaseComplete = true;
            } finally {
                if (interfacePhases) interfacePhase(name, phaseComplete ? "completed" : "failed",
                    Math.max(0L, (System.nanoTime() - phaseStarted) / 1000000L));
                BundledGhidraWorker.diagnosticsGuard();
            }
            index += count;
        }
        BundledGhidraWorker.exportsCompleted();
        BundledGhidraWorker.diagnosticsFinalization();
    }
    private static void interfacePhase(String name, String state, long elapsedMillis) {
        String phase = switch (name) {
            case "ExportProgramModel.java" -> "full-model";
            case "ExportNativeInterfacesV1.class" -> "listing";
            case "ExportInferredInterfacesV1.class" -> "inferred";
            default -> throw new IllegalArgumentException("Unexpected interface phase");
        };
        System.err.println("DECOMP_INTERFACE_PHASE_V1 phase=" + phase + " state=" + state +
            " elapsedMillis=" + elapsedMillis + (phase.equals("inferred") ? " collectorLifetimeMillis=120000" : ""));
    }
}

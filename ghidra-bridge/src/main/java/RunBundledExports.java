import decompengine.ghidra.BundledGhidraWorker;
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Set;

public final class RunBundledExports extends GhidraScript {
    @Override
    protected void run() throws Exception {
        BundledGhidraWorker.diagnosticsGuard();
        String[] arguments = getScriptArgs();
        if (arguments.length == 0) throw new IllegalArgumentException("No bundled exporters requested");
        // At most eight fixed phase records for the prevalidated interface route. This does
        // not replace or reset the collector's own lifetime, which starts before hashing.
        String phaseRoute = BundledExportPhaseRoute.route(arguments);
        boolean interfacePhases = "invocation9".equals(phaseRoute);
        boolean globalTypePhases = "invocation10".equals(phaseRoute);
        // Keep each exact-name exporter admission, including the ordinary owned analyzer, distinct.
        Set<String> exporters = Set.of("ExportProgramModel.java", "ExportProgramModelOwned.java",
            "ExportRecoveredCallSites.java", "ExportDecompiledC.java", "ExportNativeCallsV1.class",
            "ExportNativeInterfacesV1.class", "ExportInferredInterfacesV1.class",
            "ExportGlobalTypeObservationsV1.class");
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
            if (interfacePhases || globalTypePhases) interfacePhase(name, "started", 0L);
            try {
                String[] exporterArguments = Arrays.copyOfRange(arguments, index, index + count);
                if (name.equals("ExportNativeCallsV1.class")) {
                    // The nested source-script loader cannot load the pinned compiled collector.
                    ExportNativeCallsV1.collect(currentProgram, monitor, exporterArguments);
                } else if (name.equals("ExportNativeInterfacesV1.class")) {
                    if (interfacePhases || globalTypePhases) {
                        long allowance = interfaceByteLimit(Path.of(exporterArguments[4]).getParent(), 0L, monitor);
                        ExportNativeInterfacesV1.collectWithStagingBudget(currentProgram, monitor, exporterArguments, allowance);
                    } else ExportNativeInterfacesV1.collect(currentProgram, monitor, exporterArguments);
                } else if (name.equals("ExportInferredInterfacesV1.class")) {
                    if (interfacePhases || globalTypePhases) {
                        Path model = Path.of(exporterArguments[8]);
                        Path listing = Path.of(exporterArguments[9]);
                        // The inferred API already charges these three files. Subtract all other
                        // retained reports and reserve both growing streams, without double charging.
                        long included = Math.addExact(Files.size(model), Math.addExact(
                            Files.size(listing.resolve("native-interfaces.json")), Files.size(listing.resolve("manifest.json"))));
                        long limit = interfaceByteLimit(model.getParent(), included, monitor);
                        ExportInferredInterfacesV1.collectWithByteLimit(currentProgram, monitor, exporterArguments, limit);
                    } else ExportInferredInterfacesV1.collect(currentProgram, monitor, exporterArguments);
                } else if (name.equals("ExportGlobalTypeObservationsV1.class")) {
                    if (!globalTypePhases || exporterArguments.length != 5) throw new IllegalArgumentException("global/type collector requires invocation10");
                    Path model = Path.of(exporterArguments[0]);
                    long included = Math.addExact(Files.size(model), Math.addExact(
                        Files.size(model.getParent().resolve("native-interfaces-v1/native-interfaces.json")),
                        Math.addExact(Files.size(model.getParent().resolve("native-interfaces-v1/manifest.json")),
                            Math.addExact(Files.size(model.getParent().resolve("native-inferred-interfaces-v1/native-inferred-interfaces.json")),
                                Files.size(model.getParent().resolve("native-inferred-interfaces-v1/manifest.json"))))));
                    long aggregateAllowance = interfaceByteLimit(model.getParent(), included, monitor) - included;
                    ExportGlobalTypeObservationsV1.collectWithByteLimit(currentProgram, monitor, exporterArguments, aggregateAllowance);
                } else {
                    runScript(name, exporterArguments);
                }
                phaseComplete = true;
            } finally {
                if (interfacePhases || globalTypePhases) interfacePhase(name, phaseComplete ? "completed" : "failed",
                    Math.max(0L, (System.nanoTime() - phaseStarted) / 1000000L));
                BundledGhidraWorker.diagnosticsGuard();
            }
            index += count;
        }
        BundledGhidraWorker.exportsCompleted();
        BundledGhidraWorker.diagnosticsFinalization();
    }

    /** Invocations 9 and 10: retained reports + live streams + collector staging share one GiB. */
    private static long interfaceByteLimit(Path reports, long includedBytes, TaskMonitor monitor) throws Exception {
        final long maximum = 1024L * 1024 * 1024;
        // The contained-command protocol bounds each stream at 64 MiB. Their current sizes
        // are not enough: either can grow while output, comparison and type spool coexist.
        final long streamReservation = 2L * 64 * 1024 * 1024;
        long retained = 0L;
        int entries = 0;
        // Finite traversal of the complete tree, including progress/state/planning/data files.
        // No symbolic links are followed; unexpected file kinds or excessive nesting fail closed.
        try (var paths = Files.walk(reports, 8)) {
            var iterator = paths.iterator();
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Path path = iterator.next();
                if (++entries > 300025) throw new IllegalStateException("interface report inventory count bound exceeded");
                BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (attributes.isDirectory()) {
                    if (!path.equals(reports) && reports.relativize(path).getNameCount() >= 8)
                        throw new IllegalStateException("interface report inventory depth bound exceeded");
                } else if (attributes.isRegularFile()) {
                    long bytes = attributes.size();
                    if (bytes < 0 || bytes > maximum - streamReservation - retained)
                        throw new IllegalStateException("interface retained reports and stream reservation exceed aggregate bound");
                    retained += bytes;
                } else throw new IllegalStateException("interface reports contain a nonregular entry");
            }
        }
        if (includedBytes < 0 || includedBytes > retained)
            throw new IllegalArgumentException("interface collector input accounting differs from retained reports");
        long available = maximum - streamReservation - retained;
        if (available == 0) throw new IllegalStateException("interface aggregate has no staging allowance");
        // Both collector APIs are lower-only. Listing charges output + live type spool +
        // manifest reservation; inferred charges its inputs + comparison staging or output
        // + manifest reservation, releasing comparison storage only after deletion.
        return available + includedBytes;
    }
    private static void interfacePhase(String name, String state, long elapsedMillis) {
        String phase = switch (name) {
            case "ExportProgramModel.java" -> "full-model";
            case "ExportNativeInterfacesV1.class" -> "listing";
            case "ExportInferredInterfacesV1.class" -> "inferred";
            case "ExportGlobalTypeObservationsV1.class" -> "global-type";
            default -> throw new IllegalArgumentException("Unexpected interface phase");
        };
        System.err.println("DECOMP_INTERFACE_PHASE_V1 phase=" + phase + " state=" + state +
            " elapsedMillis=" + elapsedMillis + (phase.equals("inferred") ? " collectorLifetimeMillis=120000" : ""));
    }
}

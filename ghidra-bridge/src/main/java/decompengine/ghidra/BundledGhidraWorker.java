package decompengine.ghidra;

import generic.stl.Pair;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class BundledGhidraWorker {
    private static boolean exportsCompleted;
    private static JvmMxBeanDiagnostics diagnostics;

    public static void exportsCompleted() {
        exportsCompleted = true;
    }

    public static void diagnosticsGuard() {
        if (diagnostics != null) diagnostics.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
    }

    public static void diagnosticsExporter(String exporter) {
        if (diagnostics != null) diagnostics.phase(JvmMxBeanDiagnostics.Phase.EXPORTER, exporter);
    }

    public static void diagnosticsFinalization() {
        if (diagnostics != null) diagnostics.phase(JvmMxBeanDiagnostics.Phase.FINALIZATION, null);
    }

    public static void main(String[] arguments) {
        if (arguments.length >= 2 && arguments[1].equals("analyze-diagnostics-v1")) {
            runWithDiagnostics(arguments);
            return;
        }
        try {
            if (arguments.length > 1 && arguments[1].equals("await-parent-launch")) {
                // A native launch may return its process handle after the parent's deadline.
                // Do not initialize Ghidra or touch project/output files without ownership.
                if (System.in.read() != '1' || System.in.read() != '\n') {
                    throw new IllegalStateException("Parent did not authorize bundled analysis launch");
                }
                String[] admitted = new String[arguments.length - 1];
                admitted[0] = arguments[0];
                System.arraycopy(arguments, 2, admitted, 1, arguments.length - 2);
                arguments = admitted;
            }
            run(arguments);
            System.exit(0);
        } catch (Exception failure) {
            failure.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void runWithDiagnostics(String[] arguments) {
        diagnostics = JvmMxBeanDiagnostics.startDefault();
        boolean success = false;
        int exitCode;
        try {
            run(arguments);
            success = true;
            exitCode = 0;
        } catch (Exception failure) {
            failure.printStackTrace(System.err);
            exitCode = 1;
        } finally {
            if (diagnostics != null) diagnostics.finish(success);
        }
        System.exit(exitCode);
    }

    private static void run(String[] arguments) throws Exception {
        if (arguments.length < 2) throw new IllegalArgumentException("Expected bundle and operation");
        validateNativeCallInvocation(arguments);
        validateInterfaceInvocation(arguments);
        probeInterfaceContainment(arguments);
        Path bundle = Path.of(arguments[0]).toAbsolutePath().normalize();
        var configuration = new HeadlessGhidraApplicationConfiguration();
        Application.initializeApplication(new GhidraApplicationLayout(bundle.toFile()), configuration);
        if (arguments.length == 2 && arguments[1].equals("probe")) {
            var languages = ghidra.program.util.DefaultLanguageService.getLanguageService();
            if (languages.getLanguageDescriptions(false).isEmpty()) {
                throw new IllegalStateException("Bundled Ghidra has no processor languages");
            }
            System.out.println("Bundled Ghidra direct API ready: " + Application.getApplicationVersion());
            return;
        }
        if (arguments.length < 8 || !(arguments[1].equals("analyze") || arguments[1].equals("analyze-diagnostics-v1"))) {
            throw new IllegalArgumentException("Expected analyze, project, name, input, scripts and post-script arguments");
        }
        Path project = Path.of(arguments[2]);
        String projectName = arguments[3];
        Path binary = Path.of(arguments[4]);
        Path scripts = Path.of(arguments[5]);
        List<Pair<String, String[]>> postScripts = new ArrayList<>();
        for (int index = 6; index < arguments.length;) {
            String script = arguments[index++];
            int count = Integer.parseInt(arguments[index++]);
            if (count < 0 || count > 16 || count > arguments.length - index) {
                throw new IllegalArgumentException("Invalid post-script argument count");
            }
            postScripts.add(new Pair<>(script, Arrays.copyOfRange(arguments, index, index + count)));
            index += count;
        }
        Path workingDirectory = Path.of("").toAbsolutePath().normalize();
        Path runRoot = workingDirectory.getParent();
        if (runRoot != null && runRoot.getFileName().toString().startsWith(".function-observation-run-")) {
            if (!workingDirectory.getFileName().toString().matches("control-[a-f0-9]{64}") ||
                !(project.equals(workingDirectory.resolve("state")) || project.equals(runRoot.resolve("state")))) {
                throw new IllegalArgumentException("Bundled project is outside the active contained state directory");
            }
        }
        Files.createDirectories(project);
        Path projectAlias = null;
        Path projectLocation = project;
        if (runRoot != null && runRoot.getFileName().toString().startsWith(".function-observation-run-")) {
            projectAlias = workingDirectory.resolve("tmp/bundled-project-location");
            Files.createSymbolicLink(projectAlias, project);
            projectLocation = Path.of("/proc/self/cwd/tmp/bundled-project-location");
        }
        HeadlessAnalyzer analyzer = HeadlessAnalyzer.getInstance();
        analyzer.getOptions().enableOverwriteOnConflict(true);
        analyzer.getOptions().setScriptDirectories(List.of(bundle.getParent().resolve("scripts").toString(), scripts.toString()));
        List<String> guardedArguments = new ArrayList<>();
        for (Pair<String, String[]> script : postScripts) {
            guardedArguments.add(script.first);
            guardedArguments.add(Integer.toString(script.second.length));
            guardedArguments.addAll(Arrays.asList(script.second));
        }
        analyzer.getOptions().setPostScriptsWithArgs(List.of(new Pair<>(
            "RunBundledExports.class", guardedArguments.toArray(String[]::new))));
        if (diagnostics != null) diagnostics.phase(JvmMxBeanDiagnostics.Phase.IMPORT_AND_ANALYSIS, null);
        try {
            analyzer.processLocal(projectLocation.toString(), projectName, "/", List.of(binary.toFile()));
        } finally {
            diagnosticsFinalization();
            if (projectAlias != null) Files.deleteIfExists(projectAlias);
        }
        if (analyzer.checkAnalysisTimedOut()) throw new IllegalStateException("Ghidra analysis timed out");
        if (!exportsCompleted) throw new IllegalStateException("Bundled Ghidra import or export failed; existing output is not a successful result");
    }

    private static boolean interfaceInvocationRequested(String[] arguments) {
        return Arrays.stream(arguments).anyMatch(value ->
            value.equals("ExportNativeInterfacesV1.class") || value.equals("ExportNativeInterfacesV1.java") ||
            value.equals("ExportInferredInterfacesV1.class") || value.equals("ExportInferredInterfacesV1.java") ||
            value.equals("ExportGlobalTypeObservationsV1.class") || value.equals("ExportGlobalTypeObservationsV1.java"));
    }

    // Fixed recovery-only probe: no paths, bypass flags, callbacks or policy arrive from the CLI.
    private static void probeInterfaceContainment(String[] arguments) throws java.io.IOException {
        if (!interfaceInvocationRequested(arguments)) return;
        String receipt = interfaceContainmentReceipt(arguments, new NioInterfaceContainmentAccess());
        System.err.println(receipt);
        if (System.err.checkError()) throw new java.io.IOException("Interface containment receipt could not be retained");
    }

    /** This private seam permits authored refusal controls, never worker/provider selection. */
    private static String interfaceContainmentReceipt(String[] arguments, InterfaceContainmentAccess access)
            throws java.io.IOException {
        validateInterfaceInvocation(arguments);
        if (!interfaceInvocationRequested(arguments)) throw new IllegalArgumentException("Interface probe requires invocation9");
        Path binary = Path.of(arguments[4]);
        Path scriptDirectory = Path.of(arguments[5]);
        if (!binary.isAbsolute() || !binary.normalize().equals(binary) || binary.getParent() == null ||
            !scriptDirectory.isAbsolute() || !scriptDirectory.normalize().equals(scriptDirectory))
            throw new IllegalArgumentException("Interface probe inputs are not canonical");
        Path exporter = scriptDirectory.resolve("ExportProgramModel.java");
        Path hidden = binary.getParent().resolve(".decomp-interface-hidden-canaries-v1");
        for (String role : new String[] {"rich", "debug", "source", "build", "oracle", "nominal"}) {
            requireUnreadable(hidden.resolve(role + ".canary"), access);
        }
        requireUnreadable(binary.getParent().resolve("gcc-driver.full"), access);
        for (Path input : new Path[] {binary, exporter}) {
            access.openReadable(input);
            if (!access.readOnly(input)) throw new IllegalStateException("Interface recovery input is on a writable filesystem");
            try {
                access.openWritable(input);
            } catch (java.nio.file.AccessDeniedException denied) {
                continue;
            } catch (java.nio.file.FileSystemException denied) {
                // The contained Linux worker has a fixed C locale; EROFS is not mapped to
                // AccessDeniedException by the default Unix file-system provider.
                if ("Read-only file system".equals(denied.getReason())) continue;
                throw denied;
            }
            throw new IllegalStateException("Interface recovery input admits a WRITE open");
        }
        // All values other than the prevalidated input digest are fixed. JSON keys are sorted;
        // no native names, paths, file contents or exception details enter this frame.
        String receipt = "DECOMP_INTERFACE_CONTAINMENT_V1 " +
            "{\"hidden\":{\"build\":true,\"debug\":true,\"fullBinary\":true,\"nominal\":true," +
            "\"oracle\":true,\"rich\":true,\"source\":true},\"inputSha256\":\"" + arguments[14] +
            "\",\"provider\":\"gcc-interface-containment-probe-v1\",\"readOnly\":{\"binary\":true," +
            "\"exporter\":true},\"schemaVersion\":1}";
        if (receipt.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + 1 > 2048)
            throw new IllegalStateException("Interface containment receipt exceeds its byte bound");
        return receipt;
    }

    private static void requireUnreadable(Path path, InterfaceContainmentAccess access) throws java.io.IOException {
        try {
            access.openReadable(path);
        } catch (java.nio.file.NoSuchFileException | java.nio.file.AccessDeniedException denied) {
            return;
        }
        throw new IllegalStateException("Hidden interface truth admits a READ open");
    }

    private interface InterfaceContainmentAccess {
        void openReadable(Path path) throws java.io.IOException;
        boolean readOnly(Path path) throws java.io.IOException;
        void openWritable(Path path) throws java.io.IOException;
    }

    private static final class NioInterfaceContainmentAccess implements InterfaceContainmentAccess {
        @Override public void openReadable(Path path) throws java.io.IOException {
            try (var ignored = java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ)) {
                // Opening alone proves visibility. Never read hidden canary contents.
            }
        }
        @Override public boolean readOnly(Path path) throws java.io.IOException {
            return Files.getFileStore(path).isReadOnly();
        }
        @Override public void openWritable(Path path) throws java.io.IOException {
            try (var ignored = java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.WRITE)) {
                // Do not create, truncate or write even when this negative control succeeds.
            }
        }
    }

    private static void validateInterfaceInvocation(String[] arguments) {
        if (!interfaceInvocationRequested(arguments)) return;
        boolean globalType = Arrays.stream(arguments).anyMatch(value -> value.equals("ExportGlobalTypeObservationsV1.class") || value.equals("ExportGlobalTypeObservationsV1.java"));
        if (arguments.length != (globalType ? 40 : 33) || !arguments[1].equals("analyze") ||
            !arguments[6].equals("ExportProgramModel.java") || !arguments[7].equals("4") ||
            !arguments[10].equals("full") || !arguments[12].equals("ExportNativeInterfacesV1.class") ||
            !arguments[13].equals("6") || !arguments[20].equals("ExportInferredInterfacesV1.class") ||
            !arguments[21].equals("11") || !arguments[15].equals(arguments[8]) ||
            !arguments[16].equals(arguments[9]) || !arguments[18].equals(arguments[11]) ||
            !arguments[22].equals(arguments[14]) || !arguments[23].equals(arguments[8]) ||
            !arguments[24].equals(arguments[9]) || !arguments[25].equals(arguments[17]) ||
            !arguments[30].equals(arguments[11]) || !arguments[31].equals(arguments[19])) {
            throw new IllegalArgumentException("Interface observations require the exact paired model-listing-inferred invocation");
        }
        for (int index : new int[] {8, 9, 14, 17, 26, 27, 28, 29}) {
            if (!arguments[index].matches("[a-f0-9]{64}"))
                throw new IllegalArgumentException("Interface observation binding digest is invalid");
        }
        Path model = Path.of(arguments[11]);
        if (!model.isAbsolute() || !model.normalize().equals(model) || model.getFileName() == null ||
            !model.getFileName().toString().equals("program_model.json") || model.getParent() == null ||
            model.getParent().getFileName() == null || !model.getParent().getFileName().toString().equals("reports") ||
            !Path.of(arguments[19]).equals(model.getParent().resolve("native-interfaces-v1")) ||
            !Path.of(arguments[32]).equals(model.getParent().resolve("native-inferred-interfaces-v1"))) {
            throw new IllegalArgumentException("Interface observation outputs differ from the paired report layout");
        }
        if (globalType) {
            if (!arguments[33].equals("ExportGlobalTypeObservationsV1.class") || !arguments[34].equals("5") ||
                !arguments[35].equals(arguments[30]) || !arguments[37].equals(arguments[22]) ||
                !arguments[38].matches("[a-f0-9]{64}") || !arguments[39].equals(arguments[24]) ||
                !Path.of(arguments[36]).equals(model.getParent().resolve("native-global-type-observations-v1.json"))) {
                throw new IllegalArgumentException("Global/type observations require the exact paired invocation10 sidecar");
            }
        }
    }

    private static void validateNativeCallInvocation(String[] arguments) {
        boolean requested = Arrays.stream(arguments).anyMatch(value ->
            value.equals("ExportNativeCallsV1.class") || value.equals("ExportNativeCallsV1.java"));
        if (!requested) return;
        if (arguments.length != 20 || !arguments[1].equals("analyze") ||
            !arguments[6].equals("ExportProgramModel.java") || !arguments[7].equals("4") ||
            !arguments[10].equals("full") || !arguments[12].equals("ExportNativeCallsV1.class") ||
            !arguments[13].equals("6") || !arguments[15].equals(arguments[8]) ||
            !arguments[16].equals(arguments[9]) || !arguments[18].equals(arguments[11])) {
            throw new IllegalArgumentException("Native call observations require the exact paired full-model invocation");
        }
        for (int index : new int[] {8, 9, 14, 17}) {
            if (!arguments[index].matches("[a-f0-9]{64}")) {
                throw new IllegalArgumentException("Native call observation binding digest is invalid");
            }
        }
        Path model = Path.of(arguments[11]);
        Path nativeDirectory = Path.of(arguments[19]);
        if (!model.isAbsolute() || !model.normalize().equals(model) ||
            model.getFileName() == null || !model.getFileName().toString().equals("program_model.json") ||
            model.getParent() == null || model.getParent().getFileName() == null ||
            !model.getParent().getFileName().toString().equals("reports") ||
            !nativeDirectory.equals(model.getParent().resolve("native-calls-v1"))) {
            throw new IllegalArgumentException("Native call observation outputs differ from the paired report layout");
        }
    }
}

// This JDK-only helper is compiled directly by the focused sampler regression tests.
final class JvmMxBeanDiagnostics {
    static final String POLICY = "jvm-mxbean-stdout-v1";
    static final String PREFIX = "DECOMP_GHIDRA_DIAGNOSTICS_V1 ";
    // The Linux diagnostic runtime uses a tighter PIPE_BUF-sized frame than the 8 KiB contract.
    static final int MAX_FRAME_BYTES = 4096;
    static final int MAX_RECORDS = 640;
    static final int MAX_PENDING_RECORDS = 16;
    static final long MAX_BYTES = 5L * 1024 * 1024;
    static final long SAMPLE_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
    static final long DRAIN_NANOS = java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(250);
    private static final int RESERVED_RECORDS = 2;
    private static final int MAX_NAMES = 32;
    private static final int MAX_NAME_CHARS = 128;

    enum Phase {
        INIT("init"), IMPORT_AND_ANALYSIS("import-and-analysis"), GUARD("guard"),
        EXPORTER("exporter"), FINALIZATION("finalization"), TERMINAL("terminal");
        final String wire;
        Phase(String wire) { this.wire = wire; }
    }

    enum Loss {
        QUEUE_SATURATION("queue_saturation"), RECORD_LIMIT("record_limit"), BYTE_LIMIT("byte_limit"),
        FRAME_LIMIT("frame_limit"), OUTPUT_FAILURE("output_failure"), DRAIN_TIMEOUT("drain_timeout"),
        INTERNAL_FAILURE("internal_failure");
        final String wire;
        Loss(String wire) { this.wire = wire; }
    }

    interface Metrics {
        java.util.Map<String, Object> initial();
        java.util.Map<String, Object> sample();
    }

    interface Sink { void write(byte[] frame) throws java.io.IOException; }

    private record Event(Phase phase, String exporter) {}
    private record Poll(Event event, boolean sealedAndEmpty) {}

    private final Metrics metrics;
    private final Sink sink;
    private final java.util.function.LongSupplier clock;
    private final long sampleNanos;
    private final long started;
    private final java.util.concurrent.locks.ReentrantLock queueLock = new java.util.concurrent.locks.ReentrantLock();
    private final java.util.ArrayDeque<Event> queue = new java.util.ArrayDeque<>(MAX_PENDING_RECORDS);
    private final java.util.concurrent.atomic.AtomicInteger activeProducers = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger losses = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicLong dropped = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicBoolean finishClaimed = new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicBoolean closing = new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.CountDownLatch drained = new java.util.concurrent.CountDownLatch(1);
    private final Thread emitter;
    private volatile Phase currentPhase = Phase.INIT;
    private volatile boolean ordinaryStopped;
    private volatile boolean outcomeSuccess;
    private volatile long drainStarted;
    // The remaining fields are exclusively owned by the emitter.
    private long sequence;
    private long elapsed;
    private long bytes;
    private int ordinaryRecords;
    private boolean truncationEmitted;

    static JvmMxBeanDiagnostics startDefault() {
        try {
            // Never close/flush stdout and never acquire System.out's PrintStream monitor.
            java.io.FileOutputStream output = new java.io.FileOutputStream(java.io.FileDescriptor.out);
            JvmMxBeanDiagnostics result = new JvmMxBeanDiagnostics(
                new JdkMetrics(), output::write, System::nanoTime, SAMPLE_NANOS);
            result.start();
            return result;
        } catch (Throwable unavailable) {
            // Diagnostics cannot change the worker's original outcome. Missing records are incomplete.
            return null;
        }
    }

    JvmMxBeanDiagnostics(Metrics metrics, Sink sink, java.util.function.LongSupplier clock, long sampleNanos) {
        if (sampleNanos <= 0) throw new IllegalArgumentException("Invalid diagnostic sample interval");
        this.metrics = metrics;
        this.sink = sink;
        this.clock = clock;
        this.sampleNanos = sampleNanos;
        this.started = clock.getAsLong();
        this.emitter = new Thread(this::emitLoop, "bundled-ghidra-jvm-diagnostics");
        this.emitter.setDaemon(true);
    }

    void start() { emitter.start(); }

    // Phase producers perform no MXBean reads, encoding, stdout calls, waits or blocking lock acquisition.
    void phase(Phase phase, String exporter) {
        activeProducers.incrementAndGet();
        try {
            if (closing.get()) return;
            if (phase == null || phase == Phase.TERMINAL || (phase == Phase.EXPORTER) != (exporter != null) ||
                (exporter != null && !exporter.equals("ExportProgramModel.java") &&
                    !exporter.equals("ExportRecoveredCallSites.java") && !exporter.equals("ExportDecompiledC.java"))) {
                lose(Loss.INTERNAL_FAILURE);
                return;
            }
            currentPhase = phase;
            if (ordinaryStopped) { drop(); return; }
            if (!queueLock.tryLock()) { lose(Loss.QUEUE_SATURATION); return; }
            try {
                if (closing.get()) return;
                // Two logical mailbox slots remain reserved for truncation and terminal.
                if (queue.size() >= MAX_PENDING_RECORDS - RESERVED_RECORDS) {
                    lose(Loss.QUEUE_SATURATION);
                    return;
                }
                queue.addLast(new Event(phase, exporter));
            } finally {
                queueLock.unlock();
            }
            java.util.concurrent.locks.LockSupport.unpark(emitter);
        } catch (Throwable unavailable) {
            lose(Loss.INTERNAL_FAILURE);
        } finally {
            activeProducers.decrementAndGet();
            if (closing.get()) java.util.concurrent.locks.LockSupport.unpark(emitter);
        }
    }

    void finish(boolean success) {
        // Publishing the closing flag seals admission: the emitter checks empty under the same
        // queue lock used by producers before constructing the final reserved records.
        if (!finishClaimed.compareAndSet(false, true)) return;
        outcomeSuccess = success;
        drainStarted = System.nanoTime();
        closing.set(true);
        java.util.concurrent.locks.LockSupport.unpark(emitter);
        try {
            long remaining = DRAIN_NANOS - (System.nanoTime() - drainStarted);
            if (remaining <= 0 || !drained.await(remaining, java.util.concurrent.TimeUnit.NANOSECONDS)) {
                mark(Loss.DRAIN_TIMEOUT);
            }
        } catch (InterruptedException interrupted) {
            mark(Loss.DRAIN_TIMEOUT);
            Thread.currentThread().interrupt();
        } catch (Throwable unavailable) {
            mark(Loss.INTERNAL_FAILURE);
        }
    }

    private void mark(Loss loss) { losses.getAndUpdate(value -> value | (1 << loss.ordinal())); }
    private void drop() { dropped.getAndUpdate(value -> value == Long.MAX_VALUE ? value : value + 1); }
    private void lose(Loss loss) { mark(loss); drop(); }

    private Poll poll() {
        queueLock.lock();
        try {
            Event event = queue.pollFirst();
            return new Poll(event, event == null && closing.get() && activeProducers.get() == 0);
        } finally { queueLock.unlock(); }
    }

    private void emitLoop() {
        try {
            emitMetrics("initial", Phase.INIT, true);
            long sampledAt = System.nanoTime();
            while (true) {
                emitTruncation();
                Poll polled = poll();
                Event event = polled.event();
                if (event != null) {
                    java.util.Map<String, Object> fields = object();
                    fields.put("exporter", event.exporter());
                    emitOrdinary("phase", event.phase(), fields);
                    continue;
                }
                if (polled.sealedAndEmpty()) {
                    // poll() observed the empty queue under its lock after admission was sealed.
                    if (System.nanoTime() - drainStarted >= DRAIN_NANOS) mark(Loss.DRAIN_TIMEOUT);
                    emitTruncation();
                    java.util.Map<String, Object> terminal = lossFields();
                    terminal.put("priorRecordsComplete", losses.get() == 0 && dropped.get() == 0);
                    // A stdout record cannot attest that its own write or final drain completed.
                    terminal.put("shutdownDrainConfirmed", false);
                    terminal.put("outcome", outcomeSuccess ? "success" : "failure");
                    emitReserved("terminal", Phase.TERMINAL, terminal);
                    return;
                }
                long sinceSample = System.nanoTime() - sampledAt;
                if (!ordinaryStopped && sinceSample >= sampleNanos) {
                    emitMetrics("sample", currentPhase, false);
                    sampledAt = System.nanoTime();
                } else {
                    long delay = ordinaryStopped ? SAMPLE_NANOS : Math.max(1, sampleNanos - sinceSample);
                    java.util.concurrent.locks.LockSupport.parkNanos(Math.min(delay, SAMPLE_NANOS));
                }
            }
        } catch (java.io.IOException outputFailure) {
            mark(Loss.OUTPUT_FAILURE);
        } catch (Throwable unavailable) {
            mark(Loss.INTERNAL_FAILURE);
        } finally {
            // Never join, flush or close the shared output descriptor.
            drained.countDown();
        }
    }

    private void emitMetrics(String kind, Phase phase, boolean initial) throws java.io.IOException {
        try { emitOrdinary(kind, phase, initial ? metrics.initial() : metrics.sample()); }
        catch (FrameLimit exceeded) { lose(Loss.FRAME_LIMIT); }
    }

    private void emitOrdinary(String kind, Phase phase, java.util.Map<String, Object> fields) throws java.io.IOException {
        if (ordinaryStopped) { drop(); return; }
        if (ordinaryRecords >= MAX_RECORDS - RESERVED_RECORDS) {
            ordinaryStopped = true;
            lose(Loss.RECORD_LIMIT);
            return;
        }
        byte[] frame;
        try { frame = frame(kind, phase, fields); }
        catch (FrameLimit exceeded) { lose(Loss.FRAME_LIMIT); return; }
        if (bytes + frame.length > MAX_BYTES - (long) RESERVED_RECORDS * MAX_FRAME_BYTES) {
            ordinaryStopped = true;
            lose(Loss.BYTE_LIMIT);
            return;
        }
        write(frame);
        ordinaryRecords++;
    }

    private java.util.Map<String, Object> lossFields() {
        java.util.Map<String, Object> fields = object();
        java.util.List<String> names = new java.util.ArrayList<>();
        int observed = losses.get();
        for (Loss loss : Loss.values()) if ((observed & (1 << loss.ordinal())) != 0) names.add(loss.wire);
        fields.put("lossReasons", names);
        fields.put("droppedRecords", dropped.get());
        return fields;
    }

    private void emitTruncation() throws java.io.IOException {
        if (losses.get() != 0 && !truncationEmitted) {
            emitReserved("truncation", currentPhase, lossFields());
            truncationEmitted = true;
        }
    }

    private void emitReserved(String kind, Phase phase, java.util.Map<String, Object> fields) throws java.io.IOException {
        byte[] frame = frame(kind, phase, fields);
        if (sequence >= MAX_RECORDS || bytes + frame.length > MAX_BYTES) throw new AssertionError("Diagnostic reserve exhausted");
        write(frame);
    }

    private void write(byte[] frame) throws java.io.IOException {
        sink.write(frame);
        bytes += frame.length;
        sequence++;
    }

    private byte[] frame(String kind, Phase phase, java.util.Map<String, Object> fields) {
        long observed = clock.getAsLong() - started;
        if (observed >= 0) elapsed = Math.max(elapsed, observed);
        java.util.Map<String, Object> record = object();
        record.put("policy", POLICY);
        record.put("sequence", sequence);
        record.put("elapsedNanos", elapsed);
        record.put("kind", kind);
        record.put("phase", phase.wire);
        record.putAll(fields);
        StringBuilder json = new StringBuilder();
        encode(json, record, 0);
        // The leading newline separates the atomic frame from unfinished ordinary stdout lines.
        byte[] frame = ("\n" + PREFIX + json + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (frame.length > MAX_FRAME_BYTES) throw new FrameLimit();
        return frame;
    }

    private static void encode(StringBuilder output, Object value, int depth) {
        if (depth > 8 || output.length() > MAX_FRAME_BYTES) throw new FrameLimit();
        if (value == null) output.append("null");
        else if (value instanceof String text) {
            if (text.length() > MAX_NAME_CHARS || text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256) throw new FrameLimit();
            output.append('"');
            for (int index = 0; index < text.length(); index++) {
                char character = text.charAt(index);
                switch (character) {
                    case '"' -> output.append("\\\"");
                    case '\\' -> output.append("\\\\");
                    case '\n' -> output.append("\\n");
                    case '\r' -> output.append("\\r");
                    case '\t' -> output.append("\\t");
                    default -> {
                        if (character < 32 || Character.isSurrogate(character)) {
                            output.append("\\u");
                            for (int shift = 12; shift >= 0; shift -= 4) output.append("0123456789abcdef".charAt((character >> shift) & 15));
                        } else output.append(character);
                    }
                }
                if (output.length() > MAX_FRAME_BYTES) throw new FrameLimit();
            }
            output.append('"');
        } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer) output.append(value);
        else if (value instanceof java.util.Map<?, ?> map) {
            output.append('{');
            boolean comma = false;
            for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
                if (comma) output.append(',');
                encode(output, entry.getKey(), depth + 1);
                output.append(':');
                encode(output, entry.getValue(), depth + 1);
                comma = true;
            }
            output.append('}');
        } else if (value instanceof java.util.List<?> list) {
            if (list.size() > MAX_NAMES) throw new FrameLimit();
            output.append('[');
            boolean comma = false;
            for (Object item : list) {
                if (comma) output.append(',');
                encode(output, item, depth + 1);
                comma = true;
            }
            output.append(']');
        } else throw new IllegalArgumentException("Unsupported diagnostic value");
        if (output.length() > MAX_FRAME_BYTES) throw new FrameLimit();
    }

    private static final class FrameLimit extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    static java.util.Map<String, Object> object() { return new java.util.LinkedHashMap<>(); }

    static final class JdkMetrics implements Metrics {
        private static Object number(long value) { return value < 0 ? null : value; }
        private static String text(java.util.function.Supplier<String> getter) {
            try { return getter.get(); } catch (RuntimeException unavailable) { return null; }
        }
        private static Object number(java.util.function.LongSupplier getter) {
            try { return number(getter.getAsLong()); } catch (RuntimeException unavailable) { return null; }
        }
        private static Object usage(java.util.function.Supplier<java.lang.management.MemoryUsage> getter) {
            try {
                java.lang.management.MemoryUsage usage = getter.get();
                if (usage == null) return null;
                java.util.Map<String, Object> result = object();
                result.put("initBytes", number(usage.getInit()));
                result.put("usedBytes", number(usage.getUsed()));
                result.put("committedBytes", number(usage.getCommitted()));
                result.put("maxBytes", number(usage.getMax()));
                return result;
            } catch (RuntimeException unavailable) { return null; }
        }
        public java.util.Map<String, Object> initial() {
            java.util.Map<String, Object> result = object();
            result.put("jvmName", text(() -> java.lang.management.ManagementFactory.getRuntimeMXBean().getVmName()));
            result.put("jvmVendor", text(() -> java.lang.management.ManagementFactory.getRuntimeMXBean().getVmVendor()));
            result.put("jvmVersion", text(() -> java.lang.management.ManagementFactory.getRuntimeMXBean().getVmVersion()));
            result.put("javaVersion", text(() -> System.getProperty("java.version")));
            result.put("processors", number(() -> Runtime.getRuntime().availableProcessors()));
            result.put("heap", usage(() -> java.lang.management.ManagementFactory.getMemoryMXBean().getHeapMemoryUsage()));
            try {
                java.util.List<String> names = new java.util.ArrayList<>();
                for (java.lang.management.GarbageCollectorMXBean collector : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
                    if (names.size() >= MAX_NAMES) throw new FrameLimit();
                    names.add(collector.getName());
                }
                names.sort(String::compareTo);
                result.put("collectors", names);
            } catch (FrameLimit bound) { throw bound; }
            catch (RuntimeException unavailable) { result.put("collectors", null); }
            return result;
        }
        public java.util.Map<String, Object> sample() {
            java.util.Map<String, Object> result = object();
            result.put("jvmCpuNanos", number(() -> {
                java.lang.management.OperatingSystemMXBean os = java.lang.management.ManagementFactory.getOperatingSystemMXBean();
                return os instanceof com.sun.management.OperatingSystemMXBean extended ? extended.getProcessCpuTime() : -1;
            }));
            result.put("heap", usage(() -> java.lang.management.ManagementFactory.getMemoryMXBean().getHeapMemoryUsage()));
            try {
                java.util.List<java.util.Map<String, Object>> pools = new java.util.ArrayList<>();
                for (java.lang.management.MemoryPoolMXBean pool : java.lang.management.ManagementFactory.getMemoryPoolMXBeans()) {
                    if (pools.size() >= MAX_NAMES) throw new FrameLimit();
                    java.util.Map<String, Object> record = object();
                    record.put("name", java.util.Objects.requireNonNull(pool.getName()));
                    record.put("type", pool.getType().name());
                    record.put("valid", pool.isValid());
                    record.put("usage", usage(pool::getUsage));
                    record.put("postGc", usage(pool::getCollectionUsage));
                    pools.add(record);
                }
                pools.sort(java.util.Comparator.comparing(item -> (String) item.get("name")));
                result.put("pools", pools);
            } catch (FrameLimit bound) { throw bound; }
            catch (RuntimeException unavailable) { result.put("pools", null); }
            try {
                java.util.List<java.util.Map<String, Object>> collectors = new java.util.ArrayList<>();
                for (java.lang.management.GarbageCollectorMXBean collector : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
                    if (collectors.size() >= MAX_NAMES) throw new FrameLimit();
                    java.util.Map<String, Object> record = object();
                    record.put("name", java.util.Objects.requireNonNull(collector.getName()));
                    record.put("count", number(collector::getCollectionCount));
                    record.put("timeMillis", number(collector::getCollectionTime));
                    collectors.add(record);
                }
                collectors.sort(java.util.Comparator.comparing(item -> (String) item.get("name")));
                result.put("collectors", collectors);
            } catch (FrameLimit bound) { throw bound; }
            catch (RuntimeException unavailable) { result.put("collectors", null); }
            return result;
        }
    }
}

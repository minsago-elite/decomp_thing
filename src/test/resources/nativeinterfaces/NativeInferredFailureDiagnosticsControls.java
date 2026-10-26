import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Pure controls of the production-used passive state and real monitor bridge. No native outcome is fabricated. */
final class NativeInferredFailureDiagnosticsControls {
    private static final String PREFIX = "DECOMP_INFERRED_FAILURE_V1 ";
    private static final long LIMIT = 120000L * 1000000L;
    private static final List<String> CASES = new ArrayList<>();

    static void run(Path root) throws Exception {
        Files.createDirectory(root);
        beforeCensus();
        preCallRefusal();
        inFlightException();
        returnBeforeCheckpointFailure();
        observedTimeoutBeforeExtractionFailure();
        stageAccountingAndFirstFreeze();
        boundedSlowCalls();
        largestStateAndRendering();
        emissionOnceAndSuccessSilence();
        emissionFailureIsSecondary();
        bridgeExceptionOrder();
        bridgeTrueShortCircuit();
        bridgeFalseDeadline();
        bridgeCheckDeadline();
        invalidPassiveStateOmitsDiagnostic();
        JsonObject receipt = new JsonObject();
        receipt.addProperty("kind", "authored-inferred-failure-diagnostics-controls-v1");
        receipt.addProperty("fixtureOnly", true);
        receipt.addProperty("nativeExecutionClaimed", false);
        receipt.addProperty("productionInterfacesAdmitted", false);
        receipt.addProperty("releaseEligible", false);
        JsonArray cases = new JsonArray();
        for (String name : CASES) cases.add(name);
        receipt.add("cases", cases);
        Files.writeString(root.resolve("pure-controls.json"), receipt + "\n");
    }

    private static ExportInferredInterfacesV1.FailureDiagnostics fresh() {
        return new ExportInferredInterfacesV1.FailureDiagnostics(0);
    }
    private static ExportInferredInterfacesV1.FailureDiagnostics prepared() {
        var d = fresh();
        d.censusReported(3); d.censusInventoried(3); d.censusValidated();
        d.function(1, 2, 0xfffffffffffffff0L);
        return d;
    }
    private static JsonObject parsed(ExportInferredInterfacesV1.FailureDiagnostics d) {
        String frame = d.frame();
        require(frame != null && frame.startsWith(PREFIX) && frame.endsWith("\n"), "missing bounded frame");
        byte[] bytes = frame.getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= 4096, "rendered framed bytes exceeded 4096");
        for (byte value : bytes) require(value >= 0 && value < 128, "frame is not bounded ASCII");
        JsonObject result = JsonParser.parseString(frame.substring(PREFIX.length())).getAsJsonObject();
        require(result.get("schemaVersion").getAsInt() == 1 && result.get("authority").getAsString().equals("diagnostic-only") &&
            !result.get("complete").getAsBoolean() && !result.get("productionInterfacesAdmitted").getAsBoolean() &&
            !result.get("releaseEligible").getAsBoolean(), "diagnostic minted authority");
        return result;
    }
    private static long number(JsonObject root, String object, String field) {
        return root.getAsJsonObject(object).get(field).getAsLong();
    }
    private static void beforeCensus() {
        var d = fresh();
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 10);
        var frame = parsed(d);
        require(frame.getAsJsonObject("census").get("reportedFunctions").isJsonNull() &&
            frame.getAsJsonObject("census").get("inventoriedFunctions").isJsonNull() &&
            !frame.getAsJsonObject("census").get("validated").getAsBoolean() && frame.get("currentFunction").isJsonNull(),
            "early failure invented native census or current function");
        CASES.add("failure-before-census-retains-unknowns");
    }
    private static void preCallRefusal() {
        var d = prepared();
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.NATIVE_PRECHECK, 119000000000L);
        d.allocation(0);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.INSUFFICIENT_WHOLE_SECOND, 119017000000L);
        var frame = parsed(d);
        require(number(frame, "counts", "nativeCallsStarted") == 0 && number(frame, "counts", "nativeCallsReturned") == 0 &&
            frame.getAsJsonObject("clock").get("currentCallElapsedNanos").isJsonNull() &&
            number(frame, "clock", "wholeSecondsAvailable") == 0 &&
            number(frame, "clock", "remainingNanosAtFailure") == 983000000L &&
            frame.getAsJsonObject("currentFunction").get("callState").getAsString().equals("not-started"),
            "pre-call allocation refusal was reported as native work");
        CASES.add("pre-call-zero-seconds-is-not-a-started-call");
    }
    private static void inFlightException() {
        var d = prepared();
        d.allocation(60); d.nativeStarted(100);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.NATIVE_CALL_EXCEPTION, 150);
        var frame = parsed(d);
        require(number(frame, "counts", "nativeCallsStarted") == 1 && number(frame, "counts", "nativeCallsReturned") == 0 &&
            number(frame, "clock", "currentCallElapsedNanos") == 50 && frame.getAsJsonArray("slowestReturnedCalls").size() == 0,
            "in-flight exception invented a returned native result");
        CASES.add("in-flight-exception-retains-unreturned-state");
    }
    private static void returnBeforeCheckpointFailure() {
        var d = prepared();
        d.allocation(60); d.nativeStarted(100); d.nativeReturned(140);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.CANCELLATION_OBSERVED, 150);
        String frozen = d.frame();
        d.timeoutObserved(true);
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.FUNCTION_RECORD, 900);
        d.functionRecordWritten();
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 1000);
        var frame = parsed(d);
        require(number(frame, "counts", "nativeCallsReturned") == 1 && number(frame, "counts", "functionRecordsWritten") == 0 &&
            number(frame, "clock", "currentCallElapsedNanos") == 40 &&
            frame.getAsJsonArray("slowestReturnedCalls").get(0).getAsJsonObject().get("timedOut").isJsonNull() &&
            frozen.equals(d.frame()), "unread timeout flag or returned duration changed after first checkpoint failure");
        CASES.add("returned-before-checkpoint-failure-keeps-timeout-unknown-and-duration-frozen");
    }
    private static void observedTimeoutBeforeExtractionFailure() {
        var d = prepared();
        d.allocation(60); d.nativeStarted(100); d.nativeReturned(140);
        require(d.timeoutObserved(true), "timeout observation did not preserve getter value");
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.HIGH_EXTRACTION, 145);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 300);
        var frame = parsed(d);
        require(number(frame, "clock", "currentCallElapsedNanos") == 40 &&
            frame.getAsJsonArray("slowestReturnedCalls").get(0).getAsJsonObject().get("timedOut").getAsBoolean(),
            "observed timeout lost or duration included later extraction");
        CASES.add("observed-timeout-is-distinct-from-unread-timeout");
    }
    private static void stageAccountingAndFirstFreeze() {
        var d = fresh();
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.CENSUS, 10);
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.LISTING_COMPARISON, 30);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.OPERATION_DEADLINE, 50);
        String first = d.frame();
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.PUBLICATION, 1000);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 2000);
        var frame = parsed(d);
        long total = 0;
        for (var entry : frame.getAsJsonObject("stageNanos").entrySet()) total += entry.getValue().getAsLong();
        require(total == 50 && number(frame, "stageNanos", "input-validation") == 10 &&
            number(frame, "stageNanos", "census") == 20 && number(frame, "stageNanos", "listing-comparison") == 20 &&
            first.equals(d.frame()), "stage totals overlap or cleanup overwrote first freeze");
        CASES.add("nonoverlapping-stage-totals-and-first-freeze-survive-cleanup");
    }
    private static void boundedSlowCalls() {
        var d = fresh();
        long now = 0;
        int[] durations = {10, 40, 20, 40, 30, 50};
        for (int i = 0; i < durations.length; i++) {
            d.function(i, 0, i); d.allocation(60); d.nativeStarted(now);
            now += durations[i]; d.nativeReturned(now); d.timeoutObserved(false);
            now++;
        }
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, now);
        JsonArray rows = parsed(d).getAsJsonArray("slowestReturnedCalls");
        int[] order = {5, 1, 3, 4};
        require(rows.size() == 4, "slow returned calls is not fixed to four");
        for (int i = 0; i < order.length; i++) require(rows.get(i).getAsJsonObject().get("ordinal").getAsInt() == order[i],
            "slow returned duration/ordinal tie order differs");
        CASES.add("fixed-four-returned-calls-use-deterministic-duration-ordinal-order");
    }
    private static void largestStateAndRendering() {
        var d = fresh();
        d.censusReported(131072); d.censusInventoried(131072); d.censusValidated();
        long now = 0;
        for (int i = 0; i < 131072; i++) {
            d.function(i, 255, -1L); d.allocation(60); d.nativeStarted(now++); d.nativeReturned(now++);
            d.timeoutObserved(false); d.highFunctionObserved(); d.functionRecordWritten(); d.disposition(0);
        }
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.OPERATION_DEADLINE, Long.MAX_VALUE);
        var frame = parsed(d);
        require(number(frame, "counts", "nativeCallsStarted") == 131072 && number(frame, "counts", "nativeCallsReturned") == 131072 &&
            number(frame, "counts", "functionRecordsWritten") == 131072 && number(frame, "counts", "highFunctionsObserved") == 131072 &&
            frame.getAsJsonObject("currentFunction").get("offsetBits").getAsString().equals("ffffffffffffffff") &&
            number(frame, "clock", "elapsedNanosAtFailure") == Long.MAX_VALUE,
            "largest permitted primitive state was omitted or corrupted");
        CASES.add("maximum-count-address-and-time-render-within-framed-4096-bytes");
    }
    private static void emissionOnceAndSuccessSilence() throws Exception {
        var d = fresh();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream stream = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            require(d.frame() == null, "successful state already has failure frame");
            d.emitOnce(stream); require(bytes.size() == 0, "successful state emitted diagnostics");
            d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 10);
            d.emitOnce(stream); d.emitOnce(stream);
        }
        require(bytes.toString(StandardCharsets.UTF_8).equals(d.frame()), "failure emission was omitted or repeated");
        CASES.add("success-is-silent-and-failure-emission-occurs-at-most-once");
    }
    private static void emissionFailureIsSecondary() {
        var d = fresh();
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 10);
        int[] attempts = {0};
        PrintStream broken = new PrintStream(new ByteArrayOutputStream()) {
            @Override public void print(String value) { attempts[0]++; throw new IllegalStateException("authored output failure"); }
            @Override public void write(byte[] bytes, int offset, int length) { attempts[0]++; throw new IllegalStateException("authored output failure"); }
        };
        d.emitOnce(broken); d.emitOnce(broken);
        require(attempts[0] == 1, "emission failure escaped or retried");
        CASES.add("diagnostic-output-failure-never-replaces-or-retries-original-failure");
    }
    private static void bridgeExceptionOrder() throws Exception {
        long started = System.nanoTime() - LIMIT - 1_000_000L;
        var d = new ExportInferredInterfacesV1.FailureDiagnostics(started);
        d.stage(ExportInferredInterfacesV1.FailureDiagnostics.Stage.LISTING_COMPARISON, System.nanoTime());
        CancelledException expected = new CancelledException("authored sentinel");
        int[] checks = {0}, queries = {0};
        TaskMonitor delegate = new TaskMonitorAdapter() {
            @Override public void checkCancelled() throws CancelledException { checks[0]++; throw expected; }
            @Override public boolean isCancelled() { queries[0]++; throw new AssertionError("must not re-query cancellation"); }
        };
        TaskMonitor bridge = ExportInferredInterfacesV1.diagnosticListingMonitor(delegate, d, started);
        CancelledException actual = null;
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        boolean emittedBeforeCatch = false;
        try (PrintStream capture = new PrintStream(stderr, true, StandardCharsets.UTF_8)) {
            System.setErr(capture);
            try { bridge.checkCancelled(); } catch (CancelledException failure) {
                actual = failure;
                emittedBeforeCatch = stderr.toString(StandardCharsets.UTF_8).equals(d.frame());
            }
        } finally { System.setErr(previous); }
        require(actual == expected && checks[0] == 1 && queries[0] == 0 &&
            emittedBeforeCatch && parsed(d).get("failureKind").getAsString().equals("cancellation-observed"),
            "deadline replaced direct cancellation, monitor queried twice or emission waited for later cleanup");
        CASES.add("listing-check-cancellation-preserves-first-exception-before-expired-deadline");
    }
    private static void bridgeTrueShortCircuit() {
        long started = System.nanoTime() - LIMIT - 1_000_000L;
        var d = new ExportInferredInterfacesV1.FailureDiagnostics(started);
        int[] queries = {0};
        TaskMonitor delegate = new TaskMonitorAdapter() {
            @Override public boolean isCancelled() { queries[0]++; return true; }
            @Override public void checkCancelled() { throw new AssertionError("must not change cancellation method"); }
        };
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        boolean cancelled;
        try (PrintStream capture = new PrintStream(stderr, true, StandardCharsets.UTF_8)) {
            System.setErr(capture);
            cancelled = ExportInferredInterfacesV1.diagnosticListingMonitor(delegate, d, started).isCancelled();
        } finally { System.setErr(previous); }
        require(cancelled && queries[0] == 1 && stderr.size() == 0 &&
            parsed(d).get("failureKind").getAsString().equals("cancellation-observed"), "true monitor did not short circuit deadline");
        CASES.add("listing-query-true-short-circuits-expired-deadline");
    }
    private static void bridgeFalseDeadline() {
        long started = System.nanoTime() - LIMIT - 1_000_000L;
        var d = new ExportInferredInterfacesV1.FailureDiagnostics(started);
        int[] queries = {0};
        TaskMonitor delegate = new TaskMonitorAdapter() {
            @Override public boolean isCancelled() { queries[0]++; return false; }
            @Override public void checkCancelled() { throw new AssertionError("must not change cancellation method"); }
        };
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        boolean cancelled;
        try (PrintStream capture = new PrintStream(stderr, true, StandardCharsets.UTF_8)) {
            System.setErr(capture);
            cancelled = ExportInferredInterfacesV1.diagnosticListingMonitor(delegate, d, started).isCancelled();
        } finally { System.setErr(previous); }
        require(cancelled && queries[0] == 1 && stderr.size() == 0,
            "false monitor deadline path changed query count");
        var frame = parsed(d);
        require(frame.get("failureKind").getAsString().equals("operation-deadline") &&
            number(frame, "clock", "elapsedNanosAtFailure") + number(frame, "clock", "remainingNanosAtFailure") == LIMIT,
            "deadline frame does not share one deciding guard sample");
        CASES.add("listing-query-false-deadline-freezes-one-guard-sample");
    }
    private static void bridgeCheckDeadline() throws Exception {
        long started = System.nanoTime() - LIMIT - 1_000_000L;
        var d = new ExportInferredInterfacesV1.FailureDiagnostics(started);
        int[] checks = {0};
        TaskMonitor delegate = new TaskMonitorAdapter() {
            @Override public void checkCancelled() { checks[0]++; }
            @Override public boolean isCancelled() { throw new AssertionError("must not re-query cancellation"); }
        };
        CancelledException actual = null;
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        boolean emittedBeforeCatch = false;
        try (PrintStream capture = new PrintStream(stderr, true, StandardCharsets.UTF_8)) {
            System.setErr(capture);
            try { ExportInferredInterfacesV1.diagnosticListingMonitor(delegate, d, started).checkCancelled(); }
            catch (CancelledException failure) {
                actual = failure;
                emittedBeforeCatch = stderr.toString(StandardCharsets.UTF_8).equals(d.frame());
            }
        } finally { System.setErr(previous); }
        require(actual != null && checks[0] == 1 && emittedBeforeCatch &&
            parsed(d).get("failureKind").getAsString().equals("operation-deadline"),
            "listing check deadline changed exception class/classification or emitted only after later cleanup");
        CASES.add("listing-check-deadline-preserves-cancelled-exception-type");
    }
    private static void invalidPassiveStateOmitsDiagnostic() {
        var d = fresh();
        d.function(-1, 0, 0);
        d.freeze(ExportInferredInterfacesV1.FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, 1);
        require(d.frame() == null, "invalid passive state fabricated diagnostic");
        CASES.add("invalid-passive-state-omits-diagnostic-without-product-exception");
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

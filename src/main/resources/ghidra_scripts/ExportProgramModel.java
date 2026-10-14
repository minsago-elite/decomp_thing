// Streams a deterministic, address-keyed whole-program model through durable recovery checkpoints.
// @category llm_bin_patch

import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

// PARALLEL_EXPORT_TEST_BEGIN
/** Only this coordinator prepares metadata and publishes evidence; workers return immutable results. */
/** Bounded diagnostic observations only: elapsed timers are NOT CPU or qualification facts. */
final class ExporterPhaseObservationV1 {
    enum Phase {
        METADATA_INITIAL, METADATA_RETRY,
        NATIVE_0_INITIAL, NATIVE_0_RETRY, NATIVE_1_INITIAL, NATIVE_1_RETRY,
        NATIVE_2_INITIAL, NATIVE_2_RETRY, NATIVE_3_INITIAL, NATIVE_3_RETRY,
        RENDER, FUNCTION_PUBLICATION, PROGRESS_PUBLICATION,
        GLOBAL_EXISTING, GLOBAL_FIRST_ATTEMPT, TYPE_EXISTING, TYPE_FIRST_ATTEMPT,
        IDLE_POLL_WAIT, BARRIER_POLL_WAIT
    }
    private final long[] starts = new long[Phase.values().length];
    private final long[] ends = new long[Phase.values().length];
    private final long[] elapsed = new long[Phase.values().length];
    private final long[] published = new long[2];
    private final long[] raced = new long[2];
    private int snapshots;
    private int cadence = 1;
    private boolean terminal;

    synchronized long begin(Phase phase) { starts[phase.ordinal()]++; return System.nanoTime(); }
    synchronized void end(Phase phase, long since) {
        ends[phase.ordinal()]++;
        elapsed[phase.ordinal()] += Math.max(0L, System.nanoTime() - since);
    }
    synchronized void waitElapsed(boolean barrier, long nanos) {
        int index = (barrier ? Phase.BARRIER_POLL_WAIT : Phase.IDLE_POLL_WAIT).ordinal();
        starts[index]++; ends[index]++; elapsed[index] += Math.max(0L, nanos);
    }
    synchronized void publication(boolean type, boolean race) {
        (race ? raced : published)[type ? 1 : 0]++;
    }
    synchronized void configure(int functions) { cadence = Math.max(1, (int) (((long) functions + 13L) / 14L)); }

    // At most16 snapshots *4 lines =64 fixed lines, each <=1024 characters/UTF-8 bytes.
    // Ends include exceptional returns; starts-ends is in-flight, not a success count.
    synchronized void emit(java.util.function.Consumer<String> sink, int completed, boolean terminalState,
                           boolean runReturned) {
        if (terminal || (!terminalState && (snapshots >= 15 || completed % cadence != 0))) return;
        snapshots++;
        if (terminalState) terminal = true;
        try {
            Phase[] phases = Phase.values();
            for (int group = 0; group < 4; group++) {
                StringBuilder line = new StringBuilder("program-model phase-observation-v1");
                line.append(" snapshot=").append(snapshots).append(" group=").append(group)
                    .append(" state=").append(terminalState ? (runReturned ? "RETURNED" : "FAILED_OR_INTERRUPTED") : "PARTIAL")
                    .append(" completed=").append(completed)
                    .append(" clocks=elapsed_not_cpu overlap=inclusive inflight=starts_minus_ends analyzer_cpu=UNMEASURED worker_cpu=UNMEASURED");
                for (int index = group * 5; index < Math.min(group * 5 + 5, phases.length); index++) {
                    line.append(' ').append(phases[index].name()).append('=')
                        .append(starts[index]).append('/').append(ends[index]).append('/').append(elapsed[index]);
                }
                if (group == 3) line.append(" global_published=").append(published[0])
                    .append(" type_published=").append(published[1]).append(" global_raced=").append(raced[0])
                    .append(" type_raced=").append(raced[1]);
                if (line.length() <= 1024) sink.accept(line.toString());
            }
        } catch (Throwable diagnosticFailure) { /* Diagnostics never replace the primary outcome. */ }
    }
}

final class ExporterParallelCoordinatorV1<M, R> implements AutoCloseable {
    static final int MAXIMUM_WORKERS = 4;
    static final long CLEANUP_MILLIS = 2_000;

    interface Worker<M, R> {
        R execute(M metadata, boolean retry) throws Exception;
        // Both lifecycle operations must be nonblocking; native termination is awaited below.
        void cancel();
        void dispose();
    }

    interface Source<M, R> {
        void checkCancelled() throws Exception;
        boolean accepted(int index) throws Exception;
        M prepare(int index, boolean retry) throws Exception;
        boolean metadataComplete(M metadata);
        boolean retryRequired(R result);
        boolean retrySucceeded(R result);
        void commit(int index, R result) throws Exception;
        default void observePollWait(boolean barrier, long nanos) {}
    }

    private static final class Attempt<M, R> {
        final int index;
        final M metadata;
        final R original;

        Attempt(int index, M metadata, R original) {
            this.index = index;
            this.metadata = metadata;
            this.original = original;
        }
    }

    private static final class Completed<M, R> {
        final Attempt<M, R> attempt;
        final R result;

        Completed(Attempt<M, R> attempt, R result) {
            this.attempt = attempt;
            this.result = result;
        }
    }

    private final List<Worker<M, R>> workers;
    private final ArrayBlockingQueue<Worker<M, R>> available;
    private final ExecutorService executor;
    private final ExecutorCompletionService<Completed<M, R>> completions;
    private int outstanding;
    private boolean started;
    private boolean closed;

    ExporterParallelCoordinatorV1(List<Worker<M, R>> workers) {
        if (workers.isEmpty() || workers.size() > MAXIMUM_WORKERS || workers.contains(null)) {
            throw new IllegalArgumentException("full recovery worker count must be between one and four");
        }
        this.workers = new ArrayList<>(workers);
        available = new ArrayBlockingQueue<>(workers.size());
        available.addAll(workers);
        executor = Executors.newFixedThreadPool(workers.size(), task -> {
            Thread thread = new Thread(task, "program-model-decompiler");
            // The outer isolated worker owns the final process-tree termination boundary.
            thread.setDaemon(true);
            return thread;
        });
        completions = new ExecutorCompletionService<>(executor, new ArrayBlockingQueue<>(workers.size()));
    }

    void run(int count, Source<M, R> source) throws Exception {
        if (started || closed || count < 0) throw new IllegalStateException("full recovery coordinator is not fresh");
        started = true;
        int next = 0;
        Set<Integer> metadataBarriers = new TreeSet<>();
        while (next < count || outstanding != 0) {
            source.checkCancelled();
            while (next < count && outstanding < workers.size() && metadataBarriers.isEmpty()) {
                source.checkCancelled();
                int index = next++;
                if (source.accepted(index)) continue;
                M metadata = source.prepare(index, false);
                if (!source.metadataComplete(metadata)) metadataBarriers.add(index);
                submit(new Attempt<>(index, metadata, null));
            }
            if (outstanding == 0) continue;
            long pollStarted = System.nanoTime();
            Future<Completed<M, R>> ready;
            try { ready = completions.poll(50, TimeUnit.MILLISECONDS); }
            finally { source.observePollWait(!metadataBarriers.isEmpty(), System.nanoTime() - pollStarted); }
            if (ready == null) continue;
            Completed<M, R> completed;
            try {
                completed = ready.get();
            } catch (ExecutionException failed) {
                Throwable cause = failed.getCause();
                if (cause instanceof Exception) throw (Exception) cause;
                if (cause instanceof Error) throw (Error) cause;
                throw new IllegalStateException("full recovery worker failed", cause);
            }
            outstanding--;
            source.checkCancelled();
            Attempt<M, R> attempt = completed.attempt;
            if (attempt.original == null && source.retryRequired(completed.result)) {
                // Repeat metadata recovery just as the serial exporter did before its native retry.
                // An initially incomplete metadata pass blocks later first-owner claims until here.
                M metadata = source.prepare(attempt.index, true);
                if (!source.metadataComplete(metadata)) metadataBarriers.add(attempt.index);
                submit(new Attempt<>(attempt.index, metadata, completed.result));
            } else {
                R selected = attempt.original != null && !source.retrySucceeded(completed.result)
                    ? attempt.original : completed.result;
                source.commit(attempt.index, selected);
                metadataBarriers.remove(attempt.index);
            }
        }
    }

    private void submit(Attempt<M, R> attempt) {
        if (outstanding >= workers.size()) throw new IllegalStateException("full recovery live-job bound exceeded");
        completions.submit(() -> {
            Worker<M, R> worker = available.remove();
            try {
                R result = worker.execute(attempt.metadata, attempt.original != null);
                if (result == null) throw new IllegalStateException("full recovery worker returned no result");
                return new Completed<>(attempt, result);
            } finally {
                available.add(worker);
            }
        });
        outstanding++;
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        boolean interrupted = Thread.interrupted();
        Throwable failure = null;
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CLEANUP_MILLIS);
        for (Worker<M, R> worker : workers) {
            try { worker.cancel(); }
            catch (Throwable problem) { failure = addFailure(failure, problem); }
        }
        executor.shutdownNow();
        try {
            boolean stopped = false;
            while (!stopped && System.nanoTime() < deadline) {
                try {
                    stopped = executor.awaitTermination(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                } catch (InterruptedException problem) {
                    interrupted = true;
                }
            }
            if (!stopped) failure = addFailure(failure, new IllegalStateException("full recovery workers exceeded cleanup deadline"));
        } finally {
            for (Worker<M, R> worker : workers) {
                try { worker.dispose(); }
                catch (Throwable problem) { failure = addFailure(failure, problem); }
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
        if (failure != null) throw new IllegalStateException("full recovery worker cleanup failed", failure);
    }

    private static Throwable addFailure(Throwable previous, Throwable next) {
        if (previous == null) return next;
        if (previous != next) previous.addSuppressed(next);
        return previous;
    }
}
// PARALLEL_EXPORT_TEST_END

// SEMANTIC_FINGERPRINT_TEST_BEGIN
final class ExporterSemanticFingerprintV1 {
    static final int SCHEMA_VERSION = 1;
    static final long MAXIMUM_CANONICAL_BYTES = 1024L * 1024 * 1024;
    static final int MAXIMUM_FUNCTION_RECORD_BYTES = 64 * 1024 * 1024;
    static final int MAXIMUM_EVIDENCE_RECORD_BYTES = 1024 * 1024;
    static final long MAXIMUM_UNIQUE_EVIDENCE_BYTES = 512L * 1024 * 1024;
    static final int MAXIMUM_BATCH_COMMITMENTS = 256;
    static final int MAXIMUM_BATCH_FUNCTIONS = 512;
    static final long MAXIMUM_BATCH_FRAGMENT_BYTES = 64L * 1024 * 1024;
    static final byte FUNCTION_RECORD = 1;
    static final byte GLOBAL_RECORD = 2;
    static final byte TYPE_RECORD = 3;
    static final byte FAILURE_RECORD = 4;
    static final byte TERMINAL_RECORD = 5;
    private static final byte[] DOMAIN =
        "decomp-thing/program-semantic-fingerprint/v1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BATCH_DOMAIN =
        "decomp-thing/planning-batch-commitments/v1\n".getBytes(StandardCharsets.US_ASCII);

    static final class Binding {
        final long canonicalBytes;
        final int functionCount;
        final String sha256;

        Binding(long canonicalBytes, int functionCount, String sha256) {
            this.canonicalBytes = canonicalBytes;
            this.functionCount = functionCount;
            this.sha256 = sha256;
        }
    }

    static final class FragmentCommitment {
        final long bytes;
        final String sha256;

        FragmentCommitment(long bytes, String sha256) {
            if (bytes < 0 || bytes > MAXIMUM_BATCH_FRAGMENT_BYTES) {
                throw new IllegalStateException("planning semantic fragment exceeds its byte bound");
            }
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalStateException("planning semantic fragment has an invalid SHA-256 value");
            }
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    static final class BatchCommitment {
        final int startIndex;
        final int endExclusive;
        final FragmentCommitment functions;
        final FragmentCommitment globals;
        final FragmentCommitment types;
        final FragmentCommitment failures;

        BatchCommitment(
            int startIndex,
            int endExclusive,
            FragmentCommitment functions,
            FragmentCommitment globals,
            FragmentCommitment types,
            FragmentCommitment failures
        ) {
            if (
                startIndex < 0 || endExclusive <= startIndex ||
                endExclusive - (long) startIndex > MAXIMUM_BATCH_FUNCTIONS
            ) {
                throw new IllegalStateException("planning semantic batch has invalid inventory bounds");
            }
            if (functions == null || globals == null || types == null || failures == null) {
                throw new IllegalStateException("planning semantic batch has a missing fragment commitment");
            }
            this.startIndex = startIndex;
            this.endExclusive = endExclusive;
            this.functions = functions;
            this.globals = globals;
            this.types = types;
            this.failures = failures;
        }
    }

    static BatchCommitment commitBatch(
        int startIndex,
        int endExclusive,
        String functions,
        String globals,
        String types,
        String failures
    ) throws Exception {
        return new BatchCommitment(
            startIndex,
            endExclusive,
            commitFragment(functions),
            commitFragment(globals),
            commitFragment(types),
            commitFragment(failures)
        );
    }

    static BatchCommitment bindAuthenticatedBatch(
        int startIndex,
        int endExclusive,
        long functionBytes,
        String functionSha256,
        long globalBytes,
        String globalSha256,
        long typeBytes,
        String typeSha256,
        long failureBytes,
        String failureSha256
    ) {
        return new BatchCommitment(
            startIndex,
            endExclusive,
            new FragmentCommitment(functionBytes, functionSha256),
            new FragmentCommitment(globalBytes, globalSha256),
            new FragmentCommitment(typeBytes, typeSha256),
            new FragmentCommitment(failureBytes, failureSha256)
        );
    }

    static String batchCommitmentSha256(java.util.List<BatchCommitment> batches) throws Exception {
        if (batches == null) throw new IllegalStateException("planning semantic batch commitments are null");
        if (batches.size() > MAXIMUM_BATCH_COMMITMENTS) {
            throw new IllegalStateException("planning semantic batch count exceeds its bound");
        }
        MessageDigest commitmentDigest = MessageDigest.getInstance("SHA-256");
        commitmentDigest.update(BATCH_DOMAIN);
        int nextStart = 0;
        for (BatchCommitment batch : batches) {
            if (batch.startIndex != nextStart) {
                throw new IllegalStateException("planning semantic batches are not a contiguous inventory prefix");
            }
            updateLong(commitmentDigest, batch.startIndex);
            updateLong(commitmentDigest, batch.endExclusive);
            updateFragment(commitmentDigest, batch.functions);
            updateFragment(commitmentDigest, batch.globals);
            updateFragment(commitmentDigest, batch.types);
            updateFragment(commitmentDigest, batch.failures);
            nextStart = batch.endExclusive;
        }
        return hexDigest(commitmentDigest.digest());
    }

    static void requireBatchCommitment(BatchCommitment expected, BatchCommitment actual) {
        if (
            expected.startIndex != actual.startIndex || expected.endExclusive != actual.endExclusive ||
            !sameFragment(expected.functions, actual.functions) ||
            !sameFragment(expected.globals, actual.globals) ||
            !sameFragment(expected.types, actual.types) ||
            !sameFragment(expected.failures, actual.failures)
        ) {
            throw new IllegalStateException(
                "planning batch differs from the authenticated semantic preflight: " +
                    expected.startIndex + "-" + expected.endExclusive
            );
        }
    }

    private static FragmentCommitment commitFragment(String fragment) throws Exception {
        if (fragment == null) throw new IllegalStateException("planning semantic fragment is null");
        byte[] bytes = fragment.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAXIMUM_BATCH_FRAGMENT_BYTES) {
            throw new IllegalStateException("planning semantic fragment exceeds its byte bound");
        }
        return new FragmentCommitment(
            bytes.length,
            hexDigest(MessageDigest.getInstance("SHA-256").digest(bytes))
        );
    }

    private static boolean sameFragment(FragmentCommitment expected, FragmentCommitment actual) {
        return expected.bytes == actual.bytes && expected.sha256.equals(actual.sha256);
    }

    private static void updateFragment(MessageDigest target, FragmentCommitment fragment) {
        updateLong(target, fragment.bytes);
        target.update(fragment.sha256.getBytes(StandardCharsets.US_ASCII));
    }

    private static void updateLong(MessageDigest target, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) target.update((byte) (value >>> shift));
    }

    private final MessageDigest digest;
    private final long maximumCanonicalBytes;
    private long canonicalBytes;
    private int functionCount;
    private String previousFunctionId;
    private String currentFunctionId;
    private final Map<String, String> globals = new TreeMap<>();
    private final Map<String, String> types = new TreeMap<>();
    private final Map<String, String> failures = new TreeMap<>();
    private long uniqueEvidenceBytes;
    private boolean finished;

    ExporterSemanticFingerprintV1() throws Exception {
        this(MAXIMUM_CANONICAL_BYTES);
    }

    ExporterSemanticFingerprintV1(long maximumCanonicalBytes) throws Exception {
        if (maximumCanonicalBytes < DOMAIN.length || maximumCanonicalBytes > MAXIMUM_CANONICAL_BYTES) {
            throw new IllegalArgumentException("invalid semantic-fingerprint byte bound");
        }
        this.maximumCanonicalBytes = maximumCanonicalBytes;
        this.digest = MessageDigest.getInstance("SHA-256");
        updateRaw(DOMAIN);
    }

    void beginFunction(String id, String record) {
        requireOpen();
        requireId(id, "fn_[0-9a-f]{16}", "function");
        if (previousFunctionId != null && previousFunctionId.compareTo(id) >= 0) {
            throw new IllegalStateException("semantic-fingerprint functions are not in strict address order: " + id);
        }
        appendFrame(FUNCTION_RECORD, id, record, MAXIMUM_FUNCTION_RECORD_BYTES);
        previousFunctionId = id;
        currentFunctionId = id;
        functionCount++;
    }

    void observeGlobal(String id, String record) {
        requireCurrentFunction();
        requireId(id, "global_[0-9a-f]{16}", "global");
        retainUniqueEvidence(globals, id, record, "global");
    }

    void observeType(String id, String record) {
        requireCurrentFunction();
        requireId(id, "type_[0-9a-f]{64}", "type");
        retainUniqueEvidence(types, id, record, "type");
    }

    void observeFailure(String id, String record) {
        requireCurrentFunction();
        if (!currentFunctionId.equals(id)) {
            throw new IllegalStateException("semantic-fingerprint failure is cross-paired");
        }
        retainUniqueEvidence(failures, id, record, "failure");
    }

    Binding finish(int expectedFunctionCount) {
        requireOpen();
        if (expectedFunctionCount != functionCount) {
            throw new IllegalStateException("semantic-fingerprint function count differs from its inventory");
        }
        for (Map.Entry<String, String> failure : failures.entrySet()) {
            appendFrame(FAILURE_RECORD, failure.getKey(), failure.getValue(), MAXIMUM_EVIDENCE_RECORD_BYTES);
        }
        for (Map.Entry<String, String> global : globals.entrySet()) {
            appendFrame(GLOBAL_RECORD, global.getKey(), global.getValue(), MAXIMUM_EVIDENCE_RECORD_BYTES);
        }
        for (Map.Entry<String, String> type : types.entrySet()) {
            appendFrame(TYPE_RECORD, type.getKey(), type.getValue(), MAXIMUM_EVIDENCE_RECORD_BYTES);
        }
        appendFrame(TERMINAL_RECORD, "functions", Integer.toString(functionCount), 32);
        finished = true;
        return new Binding(canonicalBytes, functionCount, hexDigest(digest.digest()));
    }

    static void requireReusableState(String existing, String expected) {
        if (existing.equals(expected)) return;
        if (existing.startsWith("{\"schemaVersion\":1,")) {
            throw new IllegalStateException(
                "legacy export state schema 1 has no whole-program semantic binding and cannot be resumed"
            );
        }
        throw new IllegalStateException("export checkpoint identity or whole-program semantic state differs");
    }

    private void requireOpen() {
        if (finished) throw new IllegalStateException("semantic fingerprint is already final");
    }

    private void requireCurrentFunction() {
        requireOpen();
        if (currentFunctionId == null) {
            throw new IllegalStateException("semantic-fingerprint evidence precedes its function");
        }
    }

    private static void requireId(String id, String pattern, String kind) {
        if (id == null || !id.matches(pattern)) {
            throw new IllegalStateException("invalid semantic-fingerprint " + kind + " identity");
        }
    }

    private void retainUniqueEvidence(Map<String, String> records, String id, String record, String kind) {
        if (record == null) throw new IllegalStateException("semantic-fingerprint record is null");
        String existing = records.get(id);
        if (existing != null) {
            if (!existing.equals(record)) {
                throw new IllegalStateException("semantic-fingerprint " + kind + " identity has conflicting records: " + id);
            }
            return;
        }
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] recordBytes = record.getBytes(StandardCharsets.UTF_8);
        if (recordBytes.length > MAXIMUM_EVIDENCE_RECORD_BYTES) {
            throw new IllegalStateException("semantic-fingerprint record exceeds its category byte bound: " + id);
        }
        long additionalBytes;
        try {
            additionalBytes = Math.addExact(17L, Math.addExact(idBytes.length, recordBytes.length));
            uniqueEvidenceBytes = Math.addExact(uniqueEvidenceBytes, additionalBytes);
        } catch (ArithmeticException overflow) {
            throw new IllegalStateException("semantic-fingerprint unique evidence byte count overflows", overflow);
        }
        if (uniqueEvidenceBytes > MAXIMUM_UNIQUE_EVIDENCE_BYTES) {
            throw new IllegalStateException("semantic fingerprint exceeds its unique-evidence byte bound");
        }
        records.put(id, record);
    }

    private void appendFrame(byte tag, String id, String record, int maximumRecordBytes) {
        if (record == null) throw new IllegalStateException("semantic-fingerprint record is null");
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] recordBytes = record.getBytes(StandardCharsets.UTF_8);
        if (recordBytes.length > maximumRecordBytes) {
            throw new IllegalStateException("semantic-fingerprint record exceeds its category byte bound: " + id);
        }
        long frameBytes;
        try {
            frameBytes = Math.addExact(17L, Math.addExact(idBytes.length, recordBytes.length));
        } catch (ArithmeticException overflow) {
            throw new IllegalStateException("semantic-fingerprint frame byte count overflows", overflow);
        }
        requireCapacity(frameBytes);
        digest.update(tag);
        updateLong(idBytes.length);
        digest.update(idBytes);
        updateLong(recordBytes.length);
        digest.update(recordBytes);
        canonicalBytes += frameBytes;
    }

    private void updateRaw(byte[] content) {
        requireCapacity(content.length);
        digest.update(content);
        canonicalBytes += content.length;
    }

    private void requireCapacity(long additionalBytes) {
        long next;
        try {
            next = Math.addExact(canonicalBytes, additionalBytes);
        } catch (ArithmeticException overflow) {
            throw new IllegalStateException("semantic-fingerprint canonical byte count overflows", overflow);
        }
        if (next > maximumCanonicalBytes) {
            throw new IllegalStateException("semantic fingerprint exceeds its canonical byte bound");
        }
    }

    private void updateLong(long value) {
        for (int shift = 56; shift >= 0; shift -= 8) digest.update((byte) (value >>> shift));
    }

    private static String hexDigest(byte[] digest) {
        StringBuilder result = new StringBuilder();
        for (byte value : digest) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
// SEMANTIC_FINGERPRINT_TEST_END

// PURE_RENDERING_TEST_BEGIN
final class ExporterPureRenderingV1 {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final Pattern TYPE_NAME_UNSAFE = Pattern.compile("[^A-Za-z0-9_]");

    private ExporterPureRenderingV1() { }

    static String addressId(String prefix, long offset) {
        char[] result = new char[prefix.length() + 16];
        prefix.getChars(0, prefix.length(), result, 0);
        for (int index = result.length - 1; index >= prefix.length(); index--) {
            result[index] = HEX[(int) (offset & 0xf)];
            offset >>>= 4;
        }
        return new String(result);
    }

    static String hexDigest(byte[] digest) {
        char[] result = new char[digest.length * 2];
        for (int index = 0; index < digest.length; index++) {
            int value = digest[index] & 0xff;
            result[index * 2] = HEX[value >>> 4];
            result[index * 2 + 1] = HEX[value & 0xf];
        }
        return new String(result);
    }

    static String typeName(String name) {
        return TYPE_NAME_UNSAFE.matcher(name).replaceAll("_");
    }
}
// PURE_RENDERING_TEST_END

public class ExportProgramModel extends GhidraScript {
    private ExporterPhaseObservationV1 phaseObservation;
    private int observedCompleted;
    private long phaseBegin(ExporterPhaseObservationV1.Phase phase) {
        return phaseObservation == null ? 0L : phaseObservation.begin(phase);
    }
    private void phaseEnd(ExporterPhaseObservationV1.Phase phase, long started) {
        if (phaseObservation != null) phaseObservation.end(phase, started);
    }
    private void emitPhases(boolean terminal, boolean returned) {
        try { if (phaseObservation != null) phaseObservation.emit(this::println, observedCompleted, terminal, returned); }
        catch (Throwable diagnosticFailure) { /* Never replace the primary outcome. */ }
    }

    private static final int EXPORTER_VERSION = 16;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final int DECOMPILE_RETRY_TIMEOUT_SECONDS = 180;
    private static final int MAXIMUM_DECOMPILE_INSTRUCTIONS = 500_000;
    private static final long MAXIMUM_FULL_FUNCTION_RECORD_BYTES = 64L * 1024 * 1024;
    private static final int PLANNING_BATCH_FUNCTIONS = 512;
    private static final long MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES = 64L * 1024 * 1024;
    private static final int MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES = 256 * 1024;
    private static final int MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES = 1024 * 1024;
    private static final int MAXIMUM_PLANNING_BATCHES = 256;
    private static final long MAXIMUM_PROGRAM_MODEL_BYTES = 512L * 1024 * 1024;
    private static final int MAXIMUM_OPEN_EVIDENCE_CURSORS = 32;
    private static final int MAXIMUM_EXPORT_STATE_BYTES = 64 * 1024;

    private static final class PlanningIntegrityException extends RuntimeException {
        PlanningIntegrityException(String message) {
            super(message);
        }
    }

    private static final class GlobalEvidence {
        final String id, name, type, initializer;
        final Address address;

        GlobalEvidence(String id, String name, Address address, String type, String initializer) {
            this.id = id;
            this.name = name;
            this.address = address;
            this.type = type;
            this.initializer = initializer;
        }
    }

    private static final class TypeEvidence {
        final String id, declaration;
        final Address sourceAddress;

        TypeEvidence(String id, String declaration, Address sourceAddress) {
            this.id = id;
            this.declaration = declaration;
            this.sourceAddress = sourceAddress;
        }
    }

    private static final class FunctionExport {
        final String record, status, failure;

        FunctionExport(String record, String status, String failure) {
            this.record = record;
            this.status = status;
            this.failure = failure;
        }
    }

    private static final class PlanningFunctionFragmentValidation {
        final long fragmentBytes;
        final String fragmentSha256;
        final int recovered, partial, failed;
        final List<String> failedFunctionIds;

        PlanningFunctionFragmentValidation(
            long fragmentBytes,
            String fragmentSha256,
            int recovered,
            int partial,
            int failed,
            List<String> failedFunctionIds
        ) {
            this.fragmentBytes = fragmentBytes;
            this.fragmentSha256 = fragmentSha256;
            this.recovered = recovered;
            this.partial = partial;
            this.failed = failed;
            this.failedFunctionIds = failedFunctionIds;
        }
    }

    private static final class PlanningEvidenceFragmentValidation {
        final long fragmentBytes;
        final String fragmentSha256;
        final List<String> ids;

        PlanningEvidenceFragmentValidation(long fragmentBytes, String fragmentSha256, List<String> ids) {
            this.fragmentBytes = fragmentBytes;
            this.fragmentSha256 = fragmentSha256;
            this.ids = ids;
        }
    }

    private static final class PlanningBatchValidation {
        final PlanningFunctionFragmentValidation functions;
        final PlanningEvidenceFragmentValidation globals, types, failures;

        PlanningBatchValidation(
            PlanningFunctionFragmentValidation functions,
            PlanningEvidenceFragmentValidation globals,
            PlanningEvidenceFragmentValidation types,
            PlanningEvidenceFragmentValidation failures
        ) {
            this.functions = functions;
            this.globals = globals;
            this.types = types;
            this.failures = failures;
        }
    }

    private static final class PlanningSemanticState {
        final ExporterSemanticFingerprintV1.Binding binding;
        final List<ExporterSemanticFingerprintV1.BatchCommitment> batches;
        final String batchCommitmentSha256;

        PlanningSemanticState(
            ExporterSemanticFingerprintV1.Binding binding,
            List<ExporterSemanticFingerprintV1.BatchCommitment> batches,
            String batchCommitmentSha256
        ) {
            this.binding = binding;
            this.batches = new ArrayList<>(batches);
            this.batchCommitmentSha256 = batchCommitmentSha256;
        }
    }

    private static final class BoundFragment {
        final Path path;
        final long bytes;
        final String sha256;
        final List<String> ids;

        BoundFragment(Path path, long bytes, String sha256, List<String> ids) {
            this.path = path;
            this.bytes = bytes;
            this.sha256 = sha256;
            this.ids = new ArrayList<>(ids);
        }
    }

    private static final class RawLine {
        final String text;
        final boolean newline;

        RawLine(String text, boolean newline) {
            this.text = text;
            this.newline = newline;
        }
    }

    private static final class BoundedOutput extends OutputStream {
        final OutputStream delegate;
        final long maximumBytes;
        long bytesWritten;

        BoundedOutput(OutputStream delegate, long maximumBytes) {
            this.delegate = delegate;
            this.maximumBytes = maximumBytes;
        }

        private void charge(int count) {
            if (count < 0 || bytesWritten > maximumBytes - count) {
                throw new PlanningIntegrityException("program model exceeds its assembly byte bound");
            }
            bytesWritten += count;
        }

        @Override
        public void write(int value) throws IOException {
            charge(1);
            delegate.write(value);
        }

        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            charge(length);
            delegate.write(bytes, offset, length);
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static final class PlanningEvidenceCursor implements AutoCloseable {
        final BoundFragment binding;
        final InputStream input;
        final MessageDigest digest;
        long bytesRead;
        int recordIndex;
        String currentId;
        String currentRecord;
        boolean verified;

        PlanningEvidenceCursor(BoundFragment binding) throws Exception {
            if (binding.ids.isEmpty()) throw new PlanningIntegrityException("canonical merge received an empty fragment");
            this.binding = binding;
            this.input = new BufferedInputStream(Files.newInputStream(binding.path), 64 * 1024);
            this.digest = MessageDigest.getInstance("SHA-256");
            try {
                advance();
            } catch (Exception failure) {
                try {
                    input.close();
                } catch (IOException ignored) {
                    // Preserve the validation failure that made this cursor unusable.
                }
                throw failure;
            }
        }

        private RawLine readLine() throws Exception {
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            while (true) {
                int next = input.read();
                if (next < 0) {
                    if (content.size() == 0) return null;
                    return decodedLine(content, false);
                }
                bytesRead++;
                if (bytesRead > binding.bytes) {
                    throw new PlanningIntegrityException("bound fragment grew during canonical merge: " + binding.path.getFileName());
                }
                digest.update((byte) next);
                if (next == '\n') return decodedLine(content, true);
                if (next == '\r') {
                    throw new PlanningIntegrityException("bound fragment is not canonical LF text: " + binding.path.getFileName());
                }
                if (content.size() >= MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES) {
                    throw new PlanningIntegrityException("planning evidence line exceeds its byte bound: " + binding.path.getFileName());
                }
                content.write(next);
            }
        }

        private RawLine decodedLine(ByteArrayOutputStream content, boolean newline) {
            byte[] bytes = content.toByteArray();
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (!java.util.Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))) {
                throw new PlanningIntegrityException("bound fragment changed to non-canonical UTF-8: " + binding.path.getFileName());
            }
            return new RawLine(text, newline);
        }

        void advance() throws Exception {
            if (verified) {
                currentId = null;
                currentRecord = null;
                return;
            }
            long recordStart = bytesRead;
            RawLine first = readLine();
            if (first == null || !first.newline || !first.text.equals("    {") || recordIndex >= binding.ids.size()) {
                throw new PlanningIntegrityException("bound evidence fragment has an invalid record count or prefix: " + binding.path.getFileName());
            }
            StringBuilder record = new StringBuilder(first.text);
            boolean hasMore;
            while (true) {
                RawLine line = readLine();
                if (line == null) {
                    throw new PlanningIntegrityException("bound evidence fragment is truncated: " + binding.path.getFileName());
                }
                record.append('\n').append(line.text);
                if (line.text.equals("    },")) {
                    if (!line.newline) {
                        throw new PlanningIntegrityException("bound evidence fragment has a truncated separator: " + binding.path.getFileName());
                    }
                    record.setLength(record.length() - 1);
                    hasMore = true;
                    break;
                }
                if (line.text.equals("    }")) {
                    if (line.newline) {
                        throw new PlanningIntegrityException("bound evidence fragment has trailing data: " + binding.path.getFileName());
                    }
                    hasMore = false;
                    break;
                }
                if (!line.newline) {
                    throw new PlanningIntegrityException("bound evidence record is truncated: " + binding.path.getFileName());
                }
            }
            if (bytesRead - recordStart > MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES + 2L) {
                throw new PlanningIntegrityException("planning evidence record exceeds its merge byte bound: " + binding.path.getFileName());
            }
            String expectedId = binding.ids.get(recordIndex);
            if (!record.toString().startsWith("    {\n      \"id\": " + json(expectedId) + ",\n")) {
                throw new PlanningIntegrityException("bound evidence identity changed during canonical merge: " + expectedId);
            }
            currentId = expectedId;
            currentRecord = record.toString();
            recordIndex++;
            if (hasMore == (recordIndex >= binding.ids.size())) {
                throw new PlanningIntegrityException("bound evidence record count changed during canonical merge: " + binding.path.getFileName());
            }
            if (!hasMore) verifyEnd();
        }

        private void verifyEnd() throws Exception {
            if (input.read() >= 0 || bytesRead != binding.bytes || !hexDigest(digest.digest()).equals(binding.sha256)) {
                throw new PlanningIntegrityException("bound evidence fragment changed during canonical merge: " + binding.path.getFileName());
            }
            verified = true;
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

    private static final class PlanningBatchEvidence {
        final Map<String, String> globals = new TreeMap<>();
        final Map<String, String> types = new TreeMap<>();
        final Map<String, String> failures = new TreeMap<>();
        final Set<String> previouslyOwnedGlobalIds;
        final Set<String> previouslyOwnedTypeIds;
        long globalBytes, typeBytes, failureBytes;

        PlanningBatchEvidence(Set<String> previouslyOwnedGlobalIds, Set<String> previouslyOwnedTypeIds) {
            this.previouslyOwnedGlobalIds = previouslyOwnedGlobalIds;
            this.previouslyOwnedTypeIds = previouslyOwnedTypeIds;
        }

        private static long retainFirstOwner(Map<String, String> records, long currentBytes, String id, String record) {
            if (records.containsKey(id)) return currentBytes;
            int recordBytes = record.getBytes(StandardCharsets.UTF_8).length;
            long nextBytes = currentBytes + (records.isEmpty() ? 0 : 2) + recordBytes;
            if (recordBytes > MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES) {
                throw new PlanningIntegrityException("planning evidence record exceeds its byte bound: " + id);
            }
            if (nextBytes > MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES) {
                throw new PlanningIntegrityException("planning evidence fragment exceeds its byte bound");
            }
            records.put(id, record);
            return nextBytes;
        }

        void retainGlobal(String id, String record) {
            if (!previouslyOwnedGlobalIds.contains(id)) globalBytes = retainFirstOwner(globals, globalBytes, id, record);
        }

        void retainType(String id, String record) {
            if (!previouslyOwnedTypeIds.contains(id)) typeBytes = retainFirstOwner(types, typeBytes, id, record);
        }

        void retainFailure(String id, String record) {
            String existing = failures.get(id);
            if (existing != null && !existing.equals(record)) {
                throw new PlanningIntegrityException("planning failure identity collision: " + id);
            }
            failureBytes = retainFirstOwner(failures, failureBytes, id, record);
        }
    }

    private static String json(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default: if (c < 0x20) out.append(String.format("\\u%04x", (int)c)); else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static String functionId(Function function) {
        return ExporterPureRenderingV1.addressId("fn_", function.getEntryPoint().getOffset());
    }

    private static String globalId(Address address) {
        return ExporterPureRenderingV1.addressId("global_", address.getOffset());
    }

    private static String hexDigest(byte[] digest) {
        return ExporterPureRenderingV1.hexDigest(digest);
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new DigestInputStream(Files.newInputStream(path), digest)) {
            byte[] buffer = new byte[64 * 1024];
            while (input.read(buffer) >= 0) {
                // DigestInputStream updates the digest while bytes are consumed.
            }
        }
        return hexDigest(digest.digest());
    }

    private static String sha256(byte[] content) throws Exception {
        return hexDigest(MessageDigest.getInstance("SHA-256").digest(content));
    }

    private static void appendStrings(StringBuilder output, Iterable<String> values) {
        boolean first = true;
        for (String value : values) {
            if (!first) output.append(", ");
            output.append(json(value));
            first = false;
        }
    }

    private static String appendFailure(String existing, String next) {
        if (next == null || next.trim().isEmpty()) return existing;
        String bounded = next.replace('\n', ' ').replace('\r', ' ').trim();
        if (bounded.length() > 2048) bounded = bounded.substring(0, 2048) + "...";
        return existing == null ? bounded : existing + "; " + bounded;
    }

    private static String exceptionMessage(String phase, Exception failure) {
        String message = failure.getMessage();
        return phase + " failed: " + failure.getClass().getSimpleName() +
            (message == null || message.trim().isEmpty() ? "" : ": " + message);
    }

    private void rethrowInfrastructureFailure(Exception failure) throws Exception {
        if (
            monitor.isCancelled() || Thread.currentThread().isInterrupted() || failure instanceof InterruptedException ||
            failure instanceof IOException ||
            failure instanceof PlanningIntegrityException
        ) throw failure;
    }

    private void retainType(
        Path typesDirectory,
        PlanningBatchEvidence planningEvidence,
        DataType type,
        Address sourceAddress
    ) throws Exception {
        if (!(type instanceof Composite) && !(type instanceof Enum) && !(type instanceof TypeDef)) return;
        String key = type.getPathName();
        String id = "type_" + sha256(key.getBytes(StandardCharsets.UTF_8));
        int length = Math.max(type.getLength(), 1);
        String cName = ExporterPureRenderingV1.typeName(type.getName());
        if (cName.isEmpty() || Character.isDigit(cName.charAt(0))) cName = "recovered_" + id;
        // Retain the exact path used for the identity without allowing a comment terminator.
        String prefix = "/* Ghidra type " + json(key).replace("/", "\\/") + " */ ";
        String declaration;
        if (type instanceof Composite) {
            declaration = prefix + "typedef struct " + cName + " { unsigned char _data[" + length + "]; } " + cName + ";";
        } else if (type instanceof Enum) {
            declaration = prefix + "typedef int " + cName + ";";
        } else {
            declaration = prefix + "typedef unsigned char " + cName + "[" + length + "];";
        }
        TypeEvidence evidence = new TypeEvidence(id, declaration, sourceAddress);
        String record = renderType(evidence);
        if (planningEvidence == null) {
            writeIfAbsentAtomic(typesDirectory.resolve(id + ".json"), record, phaseObservation, true);
        } else {
            planningEvidence.retainType(id, record);
        }
    }

    private GlobalEvidence globalAt(Address address) {
        Data data = currentProgram.getListing().getDataContaining(address);
        Address base = data == null ? address : data.getAddress();
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(base);
        String name = symbol == null ? "DAT_" + base.toString() : symbol.getName();
        String type = data == null ? "unsigned char" : data.getDataType().getDisplayName();
        String initializer = data == null ? null : data.getDefaultValueRepresentation();
        return new GlobalEvidence(globalId(base), name, base, type, initializer);
    }

    private static final class FunctionMetadata {
        final Function function;
        final String prefix, evidence, failure;
        final boolean evidenceComplete;

        FunctionMetadata(Function function, String prefix, String evidence, String failure, boolean evidenceComplete) {
            this.function = function;
            this.prefix = prefix;
            this.evidence = evidence;
            this.failure = failure;
            this.evidenceComplete = evidenceComplete;
        }
    }

    private static final class NativeOutcome {
        final String source, failure;

        NativeOutcome(String source, String failure) {
            this.source = source;
            this.failure = failure;
        }
    }

    private FunctionMetadata collectFunctionMetadata(
        Function function,
        Path globalsDirectory,
        Path typesDirectory,
        PlanningBatchEvidence planningEvidence
    ) throws Exception {
        Set<String> callIds = new TreeSet<>();
        Set<String> referencedGlobals = new TreeSet<>();
        Set<String> strings = new TreeSet<>();
        String failure = null;
        boolean evidenceComplete = true;

        try {
            for (Function target : function.getCalledFunctions(monitor)) {
                if (!target.isExternal()) callIds.add(functionId(target));
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("call recovery", problem));
        }

        try {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("program-model metadata recovery was cancelled");
                }
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    Address target = reference.getToAddress();
                    if (!target.isMemoryAddress()) continue;
                    Data data = currentProgram.getListing().getDataContaining(target);
                    if (data != null && data.hasStringValue() && data.getValue() != null) {
                        strings.add(data.getValue().toString());
                        continue;
                    }
                    if (reference.getReferenceType().isData() && currentProgram.getFunctionManager().getFunctionContaining(target) == null) {
                        GlobalEvidence global = globalAt(target);
                        String globalRecord = renderGlobal(global);
                        if (planningEvidence == null) {
                            writeIfAbsentAtomic(globalsDirectory.resolve(global.id + ".json"), globalRecord, phaseObservation, false);
                        } else {
                            planningEvidence.retainGlobal(global.id, globalRecord);
                        }
                        referencedGlobals.add(global.id);
                        if (data != null) {
                            retainType(typesDirectory, planningEvidence, data.getDataType(), global.address);
                        }
                    }
                }
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("data-reference recovery", problem));
        }

        try {
            retainType(typesDirectory, planningEvidence, function.getReturnType(), function.getEntryPoint());
            for (Parameter parameter : function.getParameters()) {
                retainType(typesDirectory, planningEvidence, parameter.getDataType(), function.getEntryPoint());
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("type recovery", problem));
        }

        StringBuilder prefix = new StringBuilder();
        prefix.append("    {\n");
        prefix.append("      \"id\": ").append(json(functionId(function))).append(",\n");
        prefix.append("      \"name\": ").append(json(function.getName())).append(",\n");
        prefix.append("      \"address\": ").append(json(String.format("0x%x", function.getEntryPoint().getOffset()))).append(",\n");
        prefix.append("      \"prototype\": ").append(json(function.getPrototypeString(false, false))).append(",\n");
        StringBuilder evidence = new StringBuilder();
        evidence.append("      \"recoveryAssessment\": \"unassessed\",\n");
        evidence.append("      \"calls\": ["); appendStrings(evidence, callIds); evidence.append("],\n");
        evidence.append("      \"referencedGlobals\": ["); appendStrings(evidence, referencedGlobals); evidence.append("],\n");
        evidence.append("      \"strings\": ["); appendStrings(evidence, strings); evidence.append("],\n");
        if ((long) prefix.length() + evidence.length() > MAXIMUM_FULL_FUNCTION_RECORD_BYTES ||
            (long) prefix.toString().getBytes(StandardCharsets.UTF_8).length +
                evidence.toString().getBytes(StandardCharsets.UTF_8).length > MAXIMUM_FULL_FUNCTION_RECORD_BYTES) {
            throw new PlanningIntegrityException("function metadata exceeds its byte bound: " + functionId(function));
        }
        return new FunctionMetadata(function, prefix.toString(), evidence.toString(), failure, evidenceComplete);
    }

    private static NativeOutcome decompileFunction(
        Function function,
        DecompInterface decompiler,
        int timeoutSeconds,
        TaskMonitor taskMonitor
    ) throws Exception {
        String source = null;
        String failure = null;
        try {
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("program-model native decompilation was cancelled");
            }
            DecompileResults result = decompiler.decompileFunction(function, timeoutSeconds, taskMonitor);
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("program-model native decompilation was cancelled");
            }
            DecompiledFunction rendered = result.decompileCompleted() ? result.getDecompiledFunction() : null;
            if (rendered != null) {
                source = rendered.getC();
                if (source != null && (source.length() > MAXIMUM_FULL_FUNCTION_RECORD_BYTES ||
                    source.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_FULL_FUNCTION_RECORD_BYTES)) {
                    throw new PlanningIntegrityException("decompiled source exceeds its byte bound");
                }
            } else {
                String detail = result.getErrorMessage();
                failure = appendFailure(null, "decompilation failed or timed out" +
                    (detail == null || detail.trim().isEmpty() ? "" : ": " + detail));
            }
        } catch (Exception problem) {
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted() ||
                problem instanceof InterruptedException || problem instanceof IOException ||
                problem instanceof PlanningIntegrityException) throw problem;
            failure = appendFailure(null, exceptionMessage("decompilation", problem));
        }
        return new NativeOutcome(source, failure);
    }

    private static FunctionExport renderFunction(FunctionMetadata metadata, NativeOutcome nativeOutcome, boolean full) {
        String source = nativeOutcome == null ? null : nativeOutcome.source;
        String failure = nativeOutcome == null ? metadata.failure : appendFailure(metadata.failure, nativeOutcome.failure);
        String status = full
            ? (source == null ? "failed" : (metadata.evidenceComplete ? "recovered" : "partial"))
            : (metadata.evidenceComplete ? "partial" : "failed");
        String record = metadata.prefix + "      \"extractionStatus\": " + json(status) + ",\n" +
            metadata.evidence + "      \"decompiledC\": " + json(source) + "\n    }";
        if (record.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_FULL_FUNCTION_RECORD_BYTES) {
            throw new PlanningIntegrityException("function record exceeds its byte bound");
        }
        return new FunctionExport(record, status, failure);
    }

    private FunctionExport exportFunction(
        Function function,
        DecompInterface decompiler,
        Path globalsDirectory,
        Path typesDirectory,
        PlanningBatchEvidence planningEvidence,
        boolean includeDecompiledC,
        int decompileTimeoutSeconds
    ) throws Exception {
        FunctionMetadata metadata = collectFunctionMetadata(function, globalsDirectory, typesDirectory, planningEvidence);
        NativeOutcome nativeOutcome = includeDecompiledC
            ? decompileFunction(function, decompiler, decompileTimeoutSeconds, monitor) : null;
        return renderFunction(metadata, nativeOutcome, includeDecompiledC);
    }

    private final class NativeWorker implements ExporterParallelCoordinatorV1.Worker<FunctionMetadata, FunctionExport> {
        private final DecompInterface decompiler = new DecompInterface();
        private final TaskMonitorAdapter taskMonitor = new TaskMonitorAdapter(true);

        private final int workerIndex;
        private final ExporterPhaseObservationV1 observation;
        NativeWorker(int workerIndex) {
            this.workerIndex = workerIndex;
            this.observation = phaseObservation;
            try {
                DecompileOptions decompileOptions = new DecompileOptions();
                decompileOptions.setMaxInstructions(MAXIMUM_DECOMPILE_INSTRUCTIONS);
                decompiler.setOptions(decompileOptions);
                decompiler.toggleSyntaxTree(false);
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Ghidra decompiler could not open the current program");
                }
            } catch (RuntimeException | Error failure) {
                decompiler.stopProcess();
                decompiler.dispose();
                throw failure;
            }
        }

        @Override
        public FunctionExport execute(FunctionMetadata metadata, boolean retry) throws Exception {
            ExporterPhaseObservationV1.Phase nativePhase = ExporterPhaseObservationV1.Phase.values()[
                ExporterPhaseObservationV1.Phase.NATIVE_0_INITIAL.ordinal() + workerIndex * 2 + (retry ? 1 : 0)];
            long started = observation.begin(nativePhase);
            NativeOutcome outcome;
            try { outcome = decompileFunction(metadata.function, decompiler,
                retry ? DECOMPILE_RETRY_TIMEOUT_SECONDS : DECOMPILE_TIMEOUT_SECONDS, taskMonitor); }
            finally { observation.end(nativePhase, started); }
            long rendering = observation.begin(ExporterPhaseObservationV1.Phase.RENDER);
            try { return renderFunction(metadata, outcome, true); }
            finally { observation.end(ExporterPhaseObservationV1.Phase.RENDER, rendering); }
        }

        @Override
        public void cancel() {
            taskMonitor.cancel();
            decompiler.stopProcess();
        }

        @Override
        public void dispose() { decompiler.dispose(); }
    }

    private ExporterParallelCoordinatorV1<FunctionMetadata, FunctionExport> createFullRecoveryCoordinator(int count) {
        List<ExporterParallelCoordinatorV1.Worker<FunctionMetadata, FunctionExport>> workers = new ArrayList<>();
        try {
            for (int index = 0; index < count; index++) workers.add(new NativeWorker(index));
            return new ExporterParallelCoordinatorV1<>(workers);
        } catch (RuntimeException | Error failure) {
            for (ExporterParallelCoordinatorV1.Worker<FunctionMetadata, FunctionExport> worker : workers) {
                try { worker.cancel(); } catch (Throwable problem) { failure.addSuppressed(problem); }
                try { worker.dispose(); } catch (Throwable problem) { failure.addSuppressed(problem); }
            }
            throw failure;
        }
    }

    private PlanningSemanticState computePlanningSemanticState(List<Function> functions) throws Exception {
        ExporterSemanticFingerprintV1 fingerprint = new ExporterSemanticFingerprintV1();
        Set<String> ownedGlobalIds = new TreeSet<>();
        Set<String> ownedTypeIds = new TreeSet<>();
        List<ExporterSemanticFingerprintV1.BatchCommitment> batches = new ArrayList<>();
        for (int start = 0; start < functions.size(); start += PLANNING_BATCH_FUNCTIONS) {
            int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, functions.size());
            PlanningBatchEvidence evidence = new PlanningBatchEvidence(ownedGlobalIds, ownedTypeIds);
            StringBuilder functionFragment = new StringBuilder();
            long functionFragmentBytes = 0;
            for (int index = start; index < end; index++) {
                if (monitor.isCancelled()) {
                    throw new InterruptedException("program semantic fingerprint was cancelled");
                }
                // A non-null planning collector keeps this preflight read-only. One collector per
                // production-sized batch mirrors exact first-owner behavior: a type record's
                // sourceAddress may legitimately differ at later references to its stable identity.
                Function function = functions.get(index);
                FunctionExport exported = exportFunction(function, null, null, null, evidence, false, DECOMPILE_TIMEOUT_SECONDS);
                String id = functionId(function);
                fingerprint.beginFunction(id, exported.record);
                functionFragmentBytes = appendBoundedPlanningRecord(
                    functionFragment,
                    functionFragmentBytes,
                    exported.record
                );
                if (exported.failure != null) {
                    String failure = renderFunctionFailure(id, exported);
                    evidence.retainFailure(id, failure);
                    fingerprint.observeFailure(id, failure);
                }
            }
            for (Map.Entry<String, String> global : evidence.globals.entrySet()) {
                fingerprint.observeGlobal(global.getKey(), global.getValue());
                if (!ownedGlobalIds.add(global.getKey())) {
                    throw new PlanningIntegrityException(
                        "semantic preflight assigned global evidence to more than one batch: " + global.getKey()
                    );
                }
            }
            for (Map.Entry<String, String> type : evidence.types.entrySet()) {
                fingerprint.observeType(type.getKey(), type.getValue());
                if (!ownedTypeIds.add(type.getKey())) {
                    throw new PlanningIntegrityException(
                        "semantic preflight assigned type evidence to more than one batch: " + type.getKey()
                    );
                }
            }
            String globalFragment = renderPlanningEvidenceFragment(evidence.globals);
            String typeFragment = renderPlanningEvidenceFragment(evidence.types);
            String failureFragment = renderPlanningEvidenceFragment(evidence.failures);
            batches.add(ExporterSemanticFingerprintV1.commitBatch(
                start,
                end,
                functionFragment.toString(),
                globalFragment,
                typeFragment,
                failureFragment
            ));
        }
        ExporterSemanticFingerprintV1.Binding binding = fingerprint.finish(functions.size());
        return new PlanningSemanticState(
            binding,
            batches,
            ExporterSemanticFingerprintV1.batchCommitmentSha256(batches)
        );
    }

    private static String renderGlobal(GlobalEvidence global) {
        return "    {\n" +
            "      \"id\": " + json(global.id) + ",\n" +
            "      \"name\": " + json(global.name) + ",\n" +
            "      \"address\": " + json(String.format("0x%x", global.address.getOffset())) + ",\n" +
            "      \"type\": " + json(global.type) + ",\n" +
            "      \"initializer\": " + json(global.initializer) + ",\n" +
            "      \"extractionStatus\": \"recovered\",\n" +
            "      \"recoveryAssessment\": \"unassessed\"\n" +
            "    }";
    }

    private static String renderType(TypeEvidence type) {
        return "    {\n" +
            "      \"id\": " + json(type.id) + ",\n" +
            "      \"declaration\": " + json(type.declaration) + ",\n" +
            "      \"sourceAddress\": " + json(String.format("0x%x", type.sourceAddress.getOffset())) + ",\n" +
            "      \"extractionStatus\": \"partial\",\n" +
            "      \"recoveryAssessment\": \"unassessed\"\n" +
            "    }";
    }

    private static String renderFunctionFailure(String id, FunctionExport exported) {
        return "    {\n" +
            "      \"id\": " + json(id) + ",\n" +
            "      \"status\": " + json(exported.status) + ",\n" +
            "      \"message\": " + json(exported.failure) + "\n" +
            "    }";
    }

    private static boolean isAcceptedRecord(Path record) throws IOException {
        return Files.isRegularFile(record) && Files.size(record) > 0;
    }

    private static String acceptedRecordStatus(Path record, String expectedId) throws IOException {
        long size = Files.size(record);
        if (size <= 0 || size > MAXIMUM_FULL_FUNCTION_RECORD_BYTES) {
            throw new IllegalStateException("accepted function record has invalid size: " + record.getFileName());
        }
        byte[] bytes = Files.readAllBytes(record);
        String text = new String(bytes, StandardCharsets.UTF_8);
        if (
            bytes.length != size || !java.util.Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8)) ||
            !text.startsWith("    {\n      \"id\": " + json(expectedId) + ",\n") ||
            !text.endsWith("\n    }") || countOccurrences(text, "\n      \"decompiledC\": ") != 1
        ) {
            throw new IllegalStateException("accepted function record is malformed or has the wrong identity: " + record.getFileName());
        }
        int recovered = countOccurrences(text, "\n      \"extractionStatus\": \"recovered\",\n");
        int partial = countOccurrences(text, "\n      \"extractionStatus\": \"partial\",\n");
        int failed = countOccurrences(text, "\n      \"extractionStatus\": \"failed\",\n");
        if (recovered + partial + failed != 1 ||
            countOccurrences(text, "\n      \"recoveryAssessment\": \"unassessed\",\n") != 1) {
            throw new IllegalStateException("accepted function record has no unique recovery status: " + record.getFileName());
        }
        return recovered == 1 ? "recovered" : (partial == 1 ? "partial" : "failed");
    }

    private static void writeIfAbsentAtomic(Path target, String content) throws IOException {
        writeIfAbsentAtomic(target, content, null, false);
    }

    private static void writeIfAbsentAtomic(Path target, String content, ExporterPhaseObservationV1 observation,
                                           boolean type) throws IOException {
        long since = System.nanoTime();
        boolean existing = Files.isRegularFile(target);
        ExporterPhaseObservationV1.Phase phase = type
            ? (existing ? ExporterPhaseObservationV1.Phase.TYPE_EXISTING : ExporterPhaseObservationV1.Phase.TYPE_FIRST_ATTEMPT)
            : (existing ? ExporterPhaseObservationV1.Phase.GLOBAL_EXISTING : ExporterPhaseObservationV1.Phase.GLOBAL_FIRST_ATTEMPT);
        // The initial existence check is included in elapsed; failed/raced first attempts are not publications.
        if (observation != null) observation.begin(phase);
        try {
            if (existing) return;
            Files.createDirectories(target.getParent());
            Path temporary = target.resolveSibling("." + target.getFileName() + "." + UUID.randomUUID() + ".tmp");
            try {
                writeAndForce(temporary, content);
                try {
                    Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException unsupported) {
                    Files.move(temporary, target);
                }
                forceDirectory(target.getParent());
                if (observation != null) observation.publication(type, false);
            } catch (FileAlreadyExistsException raced) {
                if (observation != null) observation.publication(type, true);
                Files.deleteIfExists(temporary);
            } finally {
                Files.deleteIfExists(temporary);
            }
        } finally { if (observation != null) observation.end(phase, since); }
    }

    private static void writeAtomic(Path target, String content) throws IOException {
        Files.createDirectories(target.getParent());
        Path temporary = target.resolveSibling("." + target.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            writeAndForce(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            forceDirectory(target.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writePlanningAtomic(Path target, String content) throws IOException {
        Files.createDirectories(target.getParent());
        Path temporary = target.resolveSibling("." + target.getFileName() + ".pending");
        Files.deleteIfExists(temporary);
        try {
            writeAndForce(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            forceDirectory(target.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeAndForce(Path path, String content) throws IOException {
        Files.write(path, content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (Exception unsupported) {
            // Atomic rename plus file fsync remains the portable baseline when directory fsync is unavailable.
        }
    }

    private static long appendBoundedPlanningRecord(StringBuilder output, long currentBytes, String record) {
        byte[] recordBytes = record.getBytes(StandardCharsets.UTF_8);
        long nextBytes = currentBytes + (output.length() == 0 ? 0 : 2) + recordBytes.length;
        if (recordBytes.length > MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES || nextBytes > MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES) {
            throw new PlanningIntegrityException("planning batch fragment exceeds its byte bound");
        }
        if (output.length() > 0) output.append(",\n");
        output.append(record);
        return nextBytes;
    }

    private static String renderPlanningEvidenceFragment(Map<String, String> records) {
        StringBuilder output = new StringBuilder();
        long bytes = 0;
        for (String record : records.values()) {
            bytes = appendBoundedPlanningRecord(output, bytes, record);
        }
        return output.toString();
    }

    private static List<Path> sortedRecords(Path directory) throws IOException {
        List<Path> records = new ArrayList<>();
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            paths.filter(path -> Files.isRegularFile(path) && path.getFileName().toString().endsWith(".json"))
                .forEach(records::add);
        }
        records.sort(Comparator.comparing(path -> path.getFileName().toString()));
        return records;
    }

    private static boolean directoryHasEntries(Path directory) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            return paths.findAny().isPresent();
        }
    }

    private static String planningBatchBaseName(int startIndex, int endExclusive) {
        return String.format("batch-%08d-%08d", startIndex, endExclusive);
    }

    private static int countOccurrences(String text, String token) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(token, offset)) >= 0) {
            count++;
            offset += token.length();
        }
        return count;
    }

    private static byte[] readPlanningFragment(Path fragmentPath, boolean allowEmpty) throws IOException {
        if (!Files.isRegularFile(fragmentPath)) {
            throw new IllegalStateException("missing planning batch fragment: " + fragmentPath.getFileName());
        }
        long size = Files.size(fragmentPath);
        if ((!allowEmpty && size <= 0) || size < 0 || size > MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES) {
            throw new IllegalStateException("planning batch fragment has invalid size: " + fragmentPath.getFileName());
        }
        byte[] bytes = Files.readAllBytes(fragmentPath);
        if (bytes.length != size) {
            throw new IllegalStateException("planning batch fragment changed while being validated: " + fragmentPath.getFileName());
        }
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, decoded.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalStateException("planning batch fragment is not canonical UTF-8: " + fragmentPath.getFileName());
        }
        return bytes;
    }

    private static PlanningFunctionFragmentValidation validatePlanningFunctionFragment(
        Path fragmentPath,
        List<String> expectedFunctionIds
    ) throws Exception {
        byte[] bytes = readPlanningFragment(fragmentPath, false);
        String fragment = new String(bytes, StandardCharsets.UTF_8);
        String recordPrefix = "    {\n      \"id\": ";
        int cursor = 0;
        int recovered = 0;
        int partial = 0;
        int failed = 0;
        List<String> failedFunctionIds = new ArrayList<>();
        for (int index = 0; index < expectedFunctionIds.size(); index++) {
            int location = fragment.indexOf(recordPrefix, cursor);
            if (
                location < 0 ||
                (index == 0 ? location != 0 : location < 2 || !fragment.substring(location - 2, location).equals(",\n"))
            ) {
                throw new IllegalStateException(
                    "planning batch fragment record order differs at index " + index + ": " + fragmentPath.getFileName()
                );
            }
            String expectedPrefix = recordPrefix + json(expectedFunctionIds.get(index)) + ",\n";
            if (!fragment.startsWith(expectedPrefix, location)) {
                throw new IllegalStateException(
                    "planning batch fragment function identity differs at index " + index + ": " + fragmentPath.getFileName()
                );
            }
            cursor = location + expectedPrefix.length();
            int nextLocation = fragment.indexOf(recordPrefix, cursor);
            int recordEnd = nextLocation < 0 ? fragment.length() : nextLocation - 2;
            if (recordEnd <= location || !fragment.substring(location, recordEnd).endsWith("\n    }")) {
                throw new IllegalStateException("planning function record is truncated: " + expectedFunctionIds.get(index));
            }
            String record = fragment.substring(location, recordEnd);
            int recordRecovered = countOccurrences(record, "\n      \"extractionStatus\": \"recovered\",\n");
            int recordPartial = countOccurrences(record, "\n      \"extractionStatus\": \"partial\",\n");
            int recordFailed = countOccurrences(record, "\n      \"extractionStatus\": \"failed\",\n");
            if (recordRecovered != 0 || recordPartial + recordFailed != 1 ||
                countOccurrences(record, "\n      \"recoveryAssessment\": \"unassessed\",\n") != 1) {
                throw new IllegalStateException("planning function record has an invalid recovery status: " + expectedFunctionIds.get(index));
            }
            if (countOccurrences(record, "\n      \"decompiledC\": null\n") != 1) {
                throw new IllegalStateException("planning function record contains a non-planning function body: " + expectedFunctionIds.get(index));
            }
            recovered += recordRecovered;
            partial += recordPartial;
            failed += recordFailed;
            if (recordFailed == 1) failedFunctionIds.add(expectedFunctionIds.get(index));
        }
        if (fragment.indexOf(recordPrefix, cursor) >= 0 || !fragment.endsWith("\n    }")) {
            throw new IllegalStateException("planning batch fragment has extra or truncated records: " + fragmentPath.getFileName());
        }
        return new PlanningFunctionFragmentValidation(
            bytes.length,
            sha256(bytes),
            recovered,
            partial,
            failed,
            failedFunctionIds
        );
    }

    private static PlanningEvidenceFragmentValidation validatePlanningEvidenceFragment(
        Path fragmentPath,
        String evidenceKind,
        String idPattern
    ) throws Exception {
        byte[] bytes = readPlanningFragment(fragmentPath, true);
        String fragment = new String(bytes, StandardCharsets.UTF_8);
        List<String> ids = new ArrayList<>();
        if (!fragment.isEmpty()) {
            String recordPrefix = "    {\n      \"id\": \"";
            int location = 0;
            String previousId = null;
            while (location < fragment.length()) {
                if (!fragment.startsWith(recordPrefix, location)) {
                    throw new IllegalStateException(evidenceKind + " fragment has a malformed record prefix: " + fragmentPath.getFileName());
                }
                int idStart = location + recordPrefix.length();
                int idEnd = fragment.indexOf("\",\n", idStart);
                if (idEnd < 0) {
                    throw new IllegalStateException(evidenceKind + " fragment has a truncated identity: " + fragmentPath.getFileName());
                }
                String id = fragment.substring(idStart, idEnd);
                if (!id.matches(idPattern) || (previousId != null && previousId.compareTo(id) >= 0)) {
                    throw new IllegalStateException(evidenceKind + " fragment identities are invalid or unordered: " + id);
                }
                int nextLocation = fragment.indexOf(recordPrefix, idEnd + 3);
                int recordEnd = nextLocation < 0 ? fragment.length() : nextLocation - 2;
                if (
                    recordEnd <= location || !fragment.substring(location, recordEnd).endsWith("\n    }") ||
                    (nextLocation >= 0 && (nextLocation < 2 || !fragment.substring(nextLocation - 2, nextLocation).equals(",\n")))
                ) {
                    throw new IllegalStateException(evidenceKind + " fragment has malformed record boundaries: " + id);
                }
                String record = fragment.substring(location, recordEnd);
                if (
                    (evidenceKind.equals("globals") && (countOccurrences(record, "\n      \"extractionStatus\": \"recovered\",\n") != 1 ||
                        countOccurrences(record, "\n      \"recoveryAssessment\": \"unassessed\"\n") != 1)) ||
                    (evidenceKind.equals("types") && (countOccurrences(record, "\n      \"extractionStatus\": \"partial\",\n") != 1 ||
                        countOccurrences(record, "\n      \"recoveryAssessment\": \"unassessed\"\n") != 1)) ||
                    (evidenceKind.equals("failures") && (
                        countOccurrences(record, "\n      \"status\": \"failed\",\n") != 1 ||
                        countOccurrences(record, "\n      \"message\": ") != 1
                    ))
                ) {
                    throw new IllegalStateException(evidenceKind + " fragment record does not satisfy its schema: " + id);
                }
                ids.add(id);
                previousId = id;
                if (nextLocation < 0) break;
                location = nextLocation;
            }
        }
        return new PlanningEvidenceFragmentValidation(bytes.length, sha256(bytes), ids);
    }

    private static String renderPlanningBatchCheckpoint(
        int startIndex,
        int endExclusive,
        List<String> functionIds,
        String stateSha256,
        String inventorySha256,
        PlanningBatchValidation validation
    ) {
        return "schemaVersion=1\n" +
            "exporterVersion=" + EXPORTER_VERSION + "\n" +
            "recoveryMode=planning\n" +
            "stateSha256=" + stateSha256 + "\n" +
            "inventorySha256=" + inventorySha256 + "\n" +
            "startIndex=" + startIndex + "\n" +
            "endExclusive=" + endExclusive + "\n" +
            "functionFragmentBytes=" + validation.functions.fragmentBytes + "\n" +
            "functionFragmentSha256=" + validation.functions.fragmentSha256 + "\n" +
            "recovered=" + validation.functions.recovered + "\n" +
            "partial=" + validation.functions.partial + "\n" +
            "failed=" + validation.functions.failed + "\n" +
            "functionIds=" + String.join(",", functionIds) + "\n" +
            "globalFragmentBytes=" + validation.globals.fragmentBytes + "\n" +
            "globalFragmentSha256=" + validation.globals.fragmentSha256 + "\n" +
            "globalIds=" + String.join(",", validation.globals.ids) + "\n" +
            "typeFragmentBytes=" + validation.types.fragmentBytes + "\n" +
            "typeFragmentSha256=" + validation.types.fragmentSha256 + "\n" +
            "typeIds=" + String.join(",", validation.types.ids) + "\n" +
            "failureFragmentBytes=" + validation.failures.fragmentBytes + "\n" +
            "failureFragmentSha256=" + validation.failures.fragmentSha256 + "\n" +
            "failureIds=" + String.join(",", validation.failures.ids) + "\n";
    }

    private static PlanningBatchValidation validatePlanningBatchFragments(
        Path functionFragmentPath,
        Path globalFragmentPath,
        Path typeFragmentPath,
        Path failureFragmentPath,
        List<String> functionIds
    ) throws Exception {
        PlanningBatchValidation validation = new PlanningBatchValidation(
            validatePlanningFunctionFragment(functionFragmentPath, functionIds),
            validatePlanningEvidenceFragment(globalFragmentPath, "globals", "global_[0-9a-f]{16}"),
            validatePlanningEvidenceFragment(typeFragmentPath, "types", "type_[0-9a-f]{64}"),
            validatePlanningEvidenceFragment(failureFragmentPath, "failures", "fn_[0-9a-f]{16}")
        );
        if (!validation.failures.ids.equals(validation.functions.failedFunctionIds)) {
            throw new IllegalStateException("planning failure diagnostics do not match failed function records");
        }
        return validation;
    }

    private static PlanningBatchValidation validatePlanningBatchPair(
        Path functionFragmentPath,
        Path globalFragmentPath,
        Path typeFragmentPath,
        Path failureFragmentPath,
        Path checkpointPath,
        int startIndex,
        int endExclusive,
        List<String> functionIds,
        String stateSha256,
        String inventorySha256
    ) throws Exception {
        PlanningBatchValidation validation = validatePlanningBatchFragments(
            functionFragmentPath,
            globalFragmentPath,
            typeFragmentPath,
            failureFragmentPath,
            functionIds
        );
        if (!Files.isRegularFile(checkpointPath)) {
            throw new IllegalStateException("missing planning batch checkpoint: " + checkpointPath.getFileName());
        }
        long checkpointBytes = Files.size(checkpointPath);
        if (checkpointBytes <= 0 || checkpointBytes > MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES) {
            throw new IllegalStateException("planning batch checkpoint has invalid size: " + checkpointPath.getFileName());
        }
        byte[] checkpointContent = Files.readAllBytes(checkpointPath);
        String actual = new String(checkpointContent, StandardCharsets.UTF_8);
        if (
            checkpointContent.length != checkpointBytes ||
            !java.util.Arrays.equals(checkpointContent, actual.getBytes(StandardCharsets.UTF_8))
        ) {
            throw new IllegalStateException("planning batch checkpoint is not stable canonical UTF-8: " + checkpointPath.getFileName());
        }
        String expected = renderPlanningBatchCheckpoint(
            startIndex,
            endExclusive,
            functionIds,
            stateSha256,
            inventorySha256,
            validation
        );
        if (!actual.equals(expected)) {
            throw new IllegalStateException("planning batch checkpoint does not authenticate its fragment: " + checkpointPath.getFileName());
        }
        return validation;
    }

    private static ExporterSemanticFingerprintV1.BatchCommitment expectedPlanningBatch(
        PlanningSemanticState semanticState,
        int startIndex,
        int endExclusive
    ) {
        if (semanticState == null || startIndex % PLANNING_BATCH_FUNCTIONS != 0) {
            throw new PlanningIntegrityException("planning batch has no authenticated semantic preflight");
        }
        int batchIndex = startIndex / PLANNING_BATCH_FUNCTIONS;
        if (batchIndex < 0 || batchIndex >= semanticState.batches.size()) {
            throw new PlanningIntegrityException("planning batch is outside the authenticated semantic preflight");
        }
        ExporterSemanticFingerprintV1.BatchCommitment expected = semanticState.batches.get(batchIndex);
        if (expected.startIndex != startIndex || expected.endExclusive != endExclusive) {
            throw new PlanningIntegrityException("planning batch bounds differ from the authenticated semantic preflight");
        }
        return expected;
    }

    private static void requirePlanningBatchMatchesSemanticState(
        ExporterSemanticFingerprintV1.BatchCommitment expected,
        PlanningBatchValidation actual
    ) {
        ExporterSemanticFingerprintV1.requireBatchCommitment(
            expected,
            ExporterSemanticFingerprintV1.bindAuthenticatedBatch(
                expected.startIndex,
                expected.endExclusive,
                actual.functions.fragmentBytes,
                actual.functions.fragmentSha256,
                actual.globals.fragmentBytes,
                actual.globals.fragmentSha256,
                actual.types.fragmentBytes,
                actual.types.fragmentSha256,
                actual.failures.fragmentBytes,
                actual.failures.fragmentSha256
            )
        );
    }

    private static String[] planningBatchArtifactSuffixes() {
        return new String[] {
            ".functions.fragment",
            ".globals.fragment",
            ".types.fragment",
            ".failures.fragment",
            ".checkpoint"
        };
    }

    private static void discardPlanningPendingFiles(Path directory, int totalFunctions) throws IOException {
        for (int start = 0; start < totalFunctions; start += PLANNING_BATCH_FUNCTIONS) {
            int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, totalFunctions);
            String baseName = planningBatchBaseName(start, end);
            for (String suffix : planningBatchArtifactSuffixes()) {
                Files.deleteIfExists(directory.resolve("." + baseName + suffix + ".pending"));
            }
        }
    }

    private static void validatePlanningBatchDirectory(Path directory, int totalFunctions) throws IOException {
        Set<String> expectedNames = new TreeSet<>();
        for (int start = 0; start < totalFunctions; start += PLANNING_BATCH_FUNCTIONS) {
            int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, totalFunctions);
            String baseName = planningBatchBaseName(start, end);
            for (String suffix : planningBatchArtifactSuffixes()) expectedNames.add(baseName + suffix);
        }
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            for (Path path : (Iterable<Path>) paths::iterator) {
                String name = path.getFileName().toString();
                if (!Files.isRegularFile(path) || !expectedNames.contains(name)) {
                    throw new IllegalStateException("unexpected planning checkpoint entry: " + name);
                }
            }
        }
    }

    private static void writeUtf8(OutputStream output, String text) throws IOException {
        output.write(text.getBytes(StandardCharsets.UTF_8));
    }

    private static BoundFragment bindCurrentFile(Path path, List<String> ids) throws Exception {
        long before = Files.size(path);
        String digest = sha256(path);
        long after = Files.size(path);
        if (before != after) throw new PlanningIntegrityException("record file changed while being bound: " + path.getFileName());
        return new BoundFragment(path, after, digest, ids);
    }

    private static void copyBoundFragment(OutputStream output, BoundFragment binding) throws Exception {
        if (!Files.isRegularFile(binding.path)) {
            throw new PlanningIntegrityException("bound fragment is missing during assembly: " + binding.path.getFileName());
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(binding.path), 64 * 1024)) {
            byte[] buffer = new byte[64 * 1024];
            while (copied < binding.bytes) {
                int requested = (int) Math.min(buffer.length, binding.bytes - copied);
                int count = input.read(buffer, 0, requested);
                if (count < 0) {
                    throw new PlanningIntegrityException("bound fragment was truncated during assembly: " + binding.path.getFileName());
                }
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                copied += count;
            }
            if (input.read() >= 0) {
                throw new PlanningIntegrityException("bound fragment grew during assembly: " + binding.path.getFileName());
            }
        }
        if (!hexDigest(digest.digest()).equals(binding.sha256)) {
            throw new PlanningIntegrityException("bound fragment hash changed during assembly: " + binding.path.getFileName());
        }
    }

    private static void verifyBoundFragment(BoundFragment binding) throws Exception {
        copyBoundFragment(OutputStream.nullOutputStream(), binding);
    }

    private static void appendBoundRecordArray(OutputStream output, List<BoundFragment> records) throws Exception {
        for (int index = 0; index < records.size(); index++) {
            copyBoundFragment(output, records.get(index));
            writeUtf8(output, index + 1 == records.size() ? "\n" : ",\n");
        }
    }

    private static void mergeCanonicalEvidenceArray(
        OutputStream output, List<BoundFragment> fragments, boolean finalArray, List<String> mergedIds
    ) throws Exception {
        if (fragments.size() > MAXIMUM_OPEN_EVIDENCE_CURSORS) {
            throw new PlanningIntegrityException("canonical merge exceeds its open-cursor bound");
        }
        List<PlanningEvidenceCursor> cursors = new ArrayList<>();
        PriorityQueue<PlanningEvidenceCursor> queue = new PriorityQueue<>(
            Comparator.comparing(cursor -> cursor.currentId)
        );
        try {
            for (BoundFragment fragment : fragments) {
                PlanningEvidenceCursor cursor = new PlanningEvidenceCursor(fragment);
                cursors.add(cursor);
                queue.add(cursor);
            }
            String previousId = null;
            while (!queue.isEmpty()) {
                PlanningEvidenceCursor cursor = queue.remove();
                if (previousId != null && previousId.compareTo(cursor.currentId) >= 0) {
                    throw new PlanningIntegrityException("canonical evidence identities are duplicated or unordered: " + cursor.currentId);
                }
                previousId = cursor.currentId;
                if (mergedIds != null) mergedIds.add(cursor.currentId);
                writeUtf8(output, cursor.currentRecord);
                cursor.advance();
                if (cursor.currentId != null) queue.add(cursor);
                if (!queue.isEmpty()) writeUtf8(output, ",\n");
                else if (finalArray) writeUtf8(output, "\n");
            }
        } finally {
            for (PlanningEvidenceCursor cursor : cursors) {
                try {
                    cursor.close();
                } catch (IOException ignored) {
                    // Integrity was checked while consuming; close errors do not change accepted bytes.
                }
            }
        }
    }

    private static void appendCanonicalEvidenceArray(
        OutputStream output, List<BoundFragment> fragments, Path temporaryDirectory
    ) throws Exception {
        if (fragments.isEmpty()) return;
        // Full recovery writes one sidecar per global/type in identity order. Streaming these
        // already sorted records avoids holding thousands of file descriptors at model assembly.
        boolean singleRecordOrder = true;
        String previousId = null;
        for (BoundFragment fragment : fragments) {
            if (fragment.ids.size() != 1 ||
                (previousId != null && previousId.compareTo(fragment.ids.get(0)) >= 0)) {
                singleRecordOrder = false;
                break;
            }
            previousId = fragment.ids.get(0);
        }
        if (singleRecordOrder) {
            for (int index = 0; index < fragments.size(); index++) {
                try (PlanningEvidenceCursor cursor = new PlanningEvidenceCursor(fragments.get(index))) {
                    writeUtf8(output, cursor.currentRecord);
                    cursor.advance();
                    writeUtf8(output, index + 1 == fragments.size() ? "\n" : ",\n");
                }
            }
            return;
        }

        List<Path> temporary = new ArrayList<>();
        try {
            List<BoundFragment> active = fragments;
            while (active.size() > MAXIMUM_OPEN_EVIDENCE_CURSORS) {
                List<BoundFragment> next = new ArrayList<>();
                for (int start = 0; start < active.size(); start += MAXIMUM_OPEN_EVIDENCE_CURSORS) {
                    List<BoundFragment> group = active.subList(
                        start, Math.min(start + MAXIMUM_OPEN_EVIDENCE_CURSORS, active.size())
                    );
                    Path path = Files.createTempFile(temporaryDirectory, ".evidence-merge-", ".fragment");
                    temporary.add(path);
                    List<String> ids = new ArrayList<>();
                    try (OutputStream merged = new BufferedOutputStream(new BoundedOutput(
                        Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING),
                        MAXIMUM_PROGRAM_MODEL_BYTES
                    ))) {
                        mergeCanonicalEvidenceArray(merged, group, false, ids);
                    }
                    next.add(bindCurrentFile(path, ids));
                }
                active = next;
            }
            mergeCanonicalEvidenceArray(output, active, true, null);
        } finally {
            for (Path path : temporary) Files.deleteIfExists(path);
        }
    }

    private static long assembledRecordArrayBytes(List<BoundFragment> fragments) {
        if (fragments.isEmpty()) return 0;
        try {
            long bytes = 1L + Math.multiplyExact(fragments.size() - 1L, 2L);
            for (BoundFragment fragment : fragments) {
                if (fragment.bytes <= 0) {
                    throw new PlanningIntegrityException("published record array contains an empty fragment");
                }
                bytes = Math.addExact(bytes, fragment.bytes);
            }
            return bytes;
        } catch (ArithmeticException overflow) {
            throw new PlanningIntegrityException("program-model assembly size overflowed");
        }
    }

    private static void assembleModel(
        Path outputPath,
        String inputSha256,
        List<BoundFragment> functions,
        List<BoundFragment> globals,
        List<BoundFragment> types,
        List<BoundFragment> auxiliaryEvidence
    ) throws Exception {
        String prefix = "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": " + json(inputSha256) + ",\n  \"functions\": [\n";
        String globalsPrefix = "  ],\n  \"globals\": [\n";
        String typesPrefix = "  ],\n  \"types\": [\n";
        String suffix = "  ]\n}\n";
        long expectedBytes;
        try {
            expectedBytes = prefix.getBytes(StandardCharsets.UTF_8).length;
            expectedBytes = Math.addExact(expectedBytes, assembledRecordArrayBytes(functions));
            expectedBytes = Math.addExact(expectedBytes, globalsPrefix.getBytes(StandardCharsets.UTF_8).length);
            expectedBytes = Math.addExact(expectedBytes, assembledRecordArrayBytes(globals));
            expectedBytes = Math.addExact(expectedBytes, typesPrefix.getBytes(StandardCharsets.UTF_8).length);
            expectedBytes = Math.addExact(expectedBytes, assembledRecordArrayBytes(types));
            expectedBytes = Math.addExact(expectedBytes, suffix.getBytes(StandardCharsets.UTF_8).length);
        } catch (ArithmeticException overflow) {
            throw new PlanningIntegrityException("program-model assembly size overflowed");
        }
        if (expectedBytes > MAXIMUM_PROGRAM_MODEL_BYTES) {
            throw new PlanningIntegrityException("program model exceeds its assembly byte bound");
        }
        Files.createDirectories(outputPath.getParent());
        Path temporary = outputPath.resolveSibling("." + outputPath.getFileName() + ".pending");
        Files.deleteIfExists(temporary);
        try {
            for (BoundFragment binding : auxiliaryEvidence) verifyBoundFragment(binding);
            BoundedOutput bounded = new BoundedOutput(
                Files.newOutputStream(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                MAXIMUM_PROGRAM_MODEL_BYTES
            );
            try (OutputStream output = new BufferedOutputStream(bounded)) {
                writeUtf8(output, prefix);
                appendBoundRecordArray(output, functions);
                writeUtf8(output, globalsPrefix);
                appendCanonicalEvidenceArray(output, globals, outputPath.getParent());
                writeUtf8(output, typesPrefix);
                appendCanonicalEvidenceArray(output, types, outputPath.getParent());
                writeUtf8(output, suffix);
            }
            if (bounded.bytesWritten != expectedBytes) {
                throw new PlanningIntegrityException("program-model assembly byte count differs from its precomputed bound");
            }
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                channel.force(true);
            }
            try {
                Files.move(temporary, outputPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, outputPath, StandardCopyOption.REPLACE_EXISTING);
            }
            forceDirectory(outputPath.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void observedProgress(Path path, String phase, int completed, int total, int recovered,
                                  int partial, int failed, int reused, String currentFunction) throws IOException {
        long started = phaseBegin(ExporterPhaseObservationV1.Phase.PROGRESS_PUBLICATION);
        try { writeProgress(path, phase, completed, total, recovered, partial, failed, reused, currentFunction); }
        finally { phaseEnd(ExporterPhaseObservationV1.Phase.PROGRESS_PUBLICATION, started); }
    }

    private static void writeProgress(
        Path progressPath,
        String phase,
        int completed,
        int total,
        int recovered,
        int partial,
        int failed,
        int reused,
        String currentFunction
    ) throws IOException {
        writePlanningAtomic(
            progressPath,
            "{\"schemaVersion\":1,\"phase\":" + json(phase) +
                ",\"completed\":" + completed +
                ",\"total\":" + total +
                ",\"recovered\":" + recovered +
                ",\"partial\":" + partial +
                ",\"failed\":" + failed +
                ",\"reused\":" + reused +
                ",\"currentFunction\":" + json(currentFunction) + "}\n"
        );
    }

    private static void writeFunctionFailure(Path failuresDirectory, String id, FunctionExport exported) throws IOException {
        Path failurePath = failuresDirectory.resolve(id + ".json");
        if (exported.failure == null) {
            Files.deleteIfExists(failurePath);
        } else {
            writeAtomic(
                failurePath,
                "{\"schemaVersion\":1,\"functionId\":" + json(id) +
                    ",\"status\":" + json(exported.status) +
                    ",\"message\":" + json(exported.failure) + "}\n"
            );
        }
    }

    private static boolean isRetryableDecompileTimeout(FunctionExport exported) {
        return exported.status.equals("failed") && exported.failure != null &&
            exported.failure.contains("decompilation failed or timed out:") &&
            exported.failure.contains("process: timeout");
    }

    @Override
    protected void run() throws Exception {
        phaseObservation = null;
        observedCompleted = 0;
        boolean returned = false;
        try { runObserved(); returned = true; }
        finally { emitPhases(true, returned); }
    }

    private void runObserved() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 4 && arguments.length != 5) {
            throw new IllegalArgumentException(
                "expected exporter SHA-256, analysis-tool SHA-256, recovery mode, output path, and optional execution policy"
            );
        }
        if (!arguments[0].matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid exporter SHA-256");
        if (!arguments[1].matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid analysis-tool SHA-256");
        String exporterSha256 = arguments[0];
        String analysisToolSha256 = arguments[1];
        String recoveryMode = arguments[2];
        if (!recoveryMode.equals("full") && !recoveryMode.equals("planning")) {
            throw new IllegalArgumentException("unsupported recovery mode");
        }
        boolean includeDecompiledC = recoveryMode.equals("full");
        if (includeDecompiledC) phaseObservation = new ExporterPhaseObservationV1();
        boolean holdFirstPlanningCheckpoint = false;
        int decompilationWorkers = 1;
        if (arguments.length == 5) {
            if (!includeDecompiledC && "hold-first-planning-checkpoint-v1".equals(arguments[4])) {
                holdFirstPlanningCheckpoint = true;
            } else if (includeDecompiledC && arguments[4].matches("full-recovery-workers-v1:[1-4]")) {
                decompilationWorkers = arguments[4].charAt(arguments[4].length() - 1) - '0';
            } else {
                throw new IllegalArgumentException("unsupported export execution policy");
            }
        }
        Path outputPath = Paths.get(arguments[3]).toAbsolutePath().normalize();
        Path stateDirectory = outputPath.resolveSibling(outputPath.getFileName() + ".export");
        Path functionsDirectory = stateDirectory.resolve("functions");
        Path planningBatchesDirectory = stateDirectory.resolve("planning-batches");
        Path globalsDirectory = stateDirectory.resolve("globals");
        Path typesDirectory = stateDirectory.resolve("types");
        Path failuresDirectory = stateDirectory.resolve("failures");
        Path progressPath = outputPath.resolveSibling(outputPath.getFileName() + ".progress.json");

        Path executablePath = Paths.get(currentProgram.getExecutablePath());
        String inputSha256 = sha256(executablePath);
        List<Function> functions = new ArrayList<>();
        List<String> functionIds = new ArrayList<>();
        String previousFunctionId = null;
        FunctionIterator inventory = currentProgram.getFunctionManager().getFunctions(true);
        while (inventory.hasNext()) {
            Function function = inventory.next();
            if (function.isExternal() || function.isThunk()) continue;
            String id = functionId(function);
            if (previousFunctionId != null && previousFunctionId.compareTo(id) >= 0) {
                throw new PlanningIntegrityException("program function inventory is not in strict address order: " + id);
            }
            functions.add(function);
            functionIds.add(id);
            previousFunctionId = id;
        }
        int total = functions.size();
        long planningBatchCount = (total + (long) PLANNING_BATCH_FUNCTIONS - 1L) / PLANNING_BATCH_FUNCTIONS;
        if (!includeDecompiledC && planningBatchCount > MAXIMUM_PLANNING_BATCHES) {
            throw new PlanningIntegrityException("program inventory exceeds the planning batch-count bound");
        }

        PlanningSemanticState planningSemanticState =
            includeDecompiledC ? null : computePlanningSemanticState(functions);
        if (
            planningSemanticState != null &&
            planningSemanticState.batches.size() != planningBatchCount
        ) {
            throw new PlanningIntegrityException("semantic preflight batch count differs from its inventory");
        }
        ExporterSemanticFingerprintV1.Binding semanticBinding =
            planningSemanticState == null ? null : planningSemanticState.binding;
        String semanticState = planningSemanticState == null ? "null" :
            "{\"schemaVersion\":" + ExporterSemanticFingerprintV1.SCHEMA_VERSION +
                ",\"scope\":\"planning-exporter-visible-program\"" +
                ",\"functionCount\":" + semanticBinding.functionCount +
                ",\"planningBatchCount\":" + planningSemanticState.batches.size() +
                ",\"canonicalBytes\":" + semanticBinding.canonicalBytes +
                ",\"sha256\":" + json(semanticBinding.sha256) +
                ",\"batchCommitmentSha256\":" + json(planningSemanticState.batchCommitmentSha256) + "}";
        String state = "{\"schemaVersion\":2,\"exporterVersion\":" + EXPORTER_VERSION +
            ",\"exporterSha256\":" + json(exporterSha256) +
            ",\"analysisToolSha256\":" + json(analysisToolSha256) +
            ",\"recoveryMode\":" + json(recoveryMode) +
            (includeDecompiledC ? ",\"decompilationWorkers\":" + decompilationWorkers : "") +
            ",\"inputSha256\":" + json(inputSha256) +
            ",\"language\":" + json(currentProgram.getLanguageID().toString()) +
            ",\"compilerSpec\":" + json(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) +
            ",\"semanticStateBinding\":" + semanticState + "}\n";
        Path statePath = stateDirectory.resolve("state.json");

        // No output-state mutation occurs until the complete planning semantic boundary has been
        // traversed and bounded above. Every resume therefore recomputes future-batch semantics
        // before this exact state comparison can authorize any checkpoint reuse.
        Files.createDirectories(functionsDirectory);
        Files.createDirectories(planningBatchesDirectory);
        Files.createDirectories(globalsDirectory);
        Files.createDirectories(typesDirectory);
        Files.createDirectories(failuresDirectory);
        if (!includeDecompiledC) Files.deleteIfExists(stateDirectory.resolve(".state.json.pending"));
        if (Files.isRegularFile(statePath)) {
            long existingBytes = Files.size(statePath);
            if (existingBytes <= 0 || existingBytes > MAXIMUM_EXPORT_STATE_BYTES) {
                throw new IllegalStateException("export checkpoint state has an invalid byte length");
            }
            byte[] existingContent = Files.readAllBytes(statePath);
            String existing = new String(existingContent, StandardCharsets.UTF_8);
            if (
                existingContent.length != existingBytes ||
                !java.util.Arrays.equals(existingContent, existing.getBytes(StandardCharsets.UTF_8))
            ) {
                throw new IllegalStateException("export checkpoint state is not stable UTF-8");
            }
            ExporterSemanticFingerprintV1.requireReusableState(existing, state);
        } else {
            if (
                directoryHasEntries(functionsDirectory) || directoryHasEntries(planningBatchesDirectory) ||
                directoryHasEntries(globalsDirectory) || directoryHasEntries(typesDirectory) ||
                directoryHasEntries(failuresDirectory)
            ) {
                throw new IllegalStateException("export checkpoints exist without an export identity");
            }
            if (includeDecompiledC) writeAtomic(statePath, state); else writePlanningAtomic(statePath, state);
        }
        String stateSha256 = sha256(state.getBytes(StandardCharsets.UTF_8));
        String inventorySha256 = sha256((String.join("\n", functionIds) + "\n").getBytes(StandardCharsets.UTF_8));
        List<BoundFragment> functionRecords = new ArrayList<>();
        List<BoundFragment> globalRecords = new ArrayList<>();
        List<BoundFragment> typeRecords = new ArrayList<>();
        List<BoundFragment> auxiliaryEvidence = new ArrayList<>();
        auxiliaryEvidence.add(bindCurrentFile(statePath, new ArrayList<>()));
        int completed = 0;
        int recovered = 0;
        int partial = 0;
        int failed = 0;
        int reused;

        if (includeDecompiledC) {
            if (directoryHasEntries(planningBatchesDirectory)) {
                throw new IllegalStateException("planning checkpoints cannot be reused by a full recovery export");
            }
            for (String id : functionIds) {
                Path record = functionsDirectory.resolve(id + ".json");
                if (!isAcceptedRecord(record)) continue;
                completed++;
                String status = acceptedRecordStatus(record, id);
                if (status.equals("recovered")) recovered++;
                else if (status.equals("partial")) partial++;
                else failed++;
            }
            reused = completed;
            observedProgress(progressPath, "decompiling", completed, total, recovered, partial, failed, reused, null);

            phaseObservation.configure(total);
            observedCompleted = completed;
            emitPhases(false, false);
            final int[] counts = { completed, recovered, partial, failed };
            final int reusedRecords = reused;
            final Map<Integer, Long> startedFunctions = new TreeMap<>();
            try (ExporterParallelCoordinatorV1<FunctionMetadata, FunctionExport> coordinator =
                createFullRecoveryCoordinator(decompilationWorkers)) {
                coordinator.run(functions.size(), new ExporterParallelCoordinatorV1.Source<FunctionMetadata, FunctionExport>() {
                    @Override
                    public void checkCancelled() throws Exception {
                        if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                            throw new InterruptedException("program-model export was cancelled");
                        }
                    }

                    @Override
                    public void observePollWait(boolean barrier, long nanos) { phaseObservation.waitElapsed(barrier, nanos); }

                    @Override
                    public boolean accepted(int index) throws Exception {
                        Path record = functionsDirectory.resolve(functionIds.get(index) + ".json");
                        return isAcceptedRecord(record);
                    }

                    @Override
                    public FunctionMetadata prepare(int index, boolean retry) throws Exception {
                        String id = functionIds.get(index);
                        if (retry) {
                            println("program-model retrying timed-out function " + id + " with " + DECOMPILE_RETRY_TIMEOUT_SECONDS + " seconds");
                        } else {
                            startedFunctions.put(index, System.nanoTime());
                        }
                        observedProgress(progressPath, "decompiling", counts[0], total, counts[1], counts[2], counts[3], reusedRecords, id);
                        ExporterPhaseObservationV1.Phase metadataPhase = retry
                            ? ExporterPhaseObservationV1.Phase.METADATA_RETRY : ExporterPhaseObservationV1.Phase.METADATA_INITIAL;
                        long metadata = phaseBegin(metadataPhase);
                        try { return collectFunctionMetadata(functions.get(index), globalsDirectory, typesDirectory, null); }
                        finally { phaseEnd(metadataPhase, metadata); }
                    }

                    @Override
                    public boolean metadataComplete(FunctionMetadata metadata) { return metadata.evidenceComplete; }

                    @Override
                    public boolean retryRequired(FunctionExport exported) { return isRetryableDecompileTimeout(exported); }

                    @Override
                    public boolean retrySucceeded(FunctionExport exported) { return !exported.status.equals("failed"); }

                    @Override
                    public void commit(int index, FunctionExport exported) throws Exception {
                        String id = functionIds.get(index);
                        long publication = phaseBegin(ExporterPhaseObservationV1.Phase.FUNCTION_PUBLICATION);
                        try {
                            writeFunctionFailure(failuresDirectory, id, exported);
                            writeAtomic(functionsDirectory.resolve(id + ".json"), exported.record);
                        } finally { phaseEnd(ExporterPhaseObservationV1.Phase.FUNCTION_PUBLICATION, publication); }
                        counts[0]++;
                        if (exported.status.equals("recovered")) counts[1]++;
                        else if (exported.status.equals("partial")) counts[2]++;
                        else counts[3]++;
                        observedProgress(progressPath, "decompiling", counts[0], total, counts[1], counts[2], counts[3], reusedRecords, null);
                        observedCompleted = counts[0];
                        emitPhases(false, false);
                        println("program-model export " + counts[0] + "/" + total + " " + id +
                            " status=" + exported.status + " elapsedNanos=" + (System.nanoTime() - startedFunctions.remove(index)));
                    }
                });
            }
            completed = counts[0];
            recovered = counts[1];
            partial = counts[2];
            failed = counts[3];
            for (String id : functionIds) {
                Path record = functionsDirectory.resolve(id + ".json");
                if (!isAcceptedRecord(record)) throw new IllegalStateException("missing durable function record: " + id);
                acceptedRecordStatus(record, id);
                functionRecords.add(bindCurrentFile(record, java.util.Collections.singletonList(id)));
            }
            for (Path record : sortedRecords(globalsDirectory)) {
                String name = record.getFileName().toString();
                globalRecords.add(bindCurrentFile(record, java.util.Collections.singletonList(name.substring(0, name.length() - 5))));
            }
            for (Path record : sortedRecords(typesDirectory)) {
                String name = record.getFileName().toString();
                typeRecords.add(bindCurrentFile(record, java.util.Collections.singletonList(name.substring(0, name.length() - 5))));
            }
            for (Path record : sortedRecords(failuresDirectory)) {
                auxiliaryEvidence.add(bindCurrentFile(record, new ArrayList<>()));
            }
        } else {
            if (
                directoryHasEntries(functionsDirectory) || directoryHasEntries(globalsDirectory) ||
                directoryHasEntries(typesDirectory) || directoryHasEntries(failuresDirectory)
            ) {
                throw new IllegalStateException("per-record recovery checkpoints cannot be reused by planning mode");
            }
            discardPlanningPendingFiles(planningBatchesDirectory, total);
            validatePlanningBatchDirectory(planningBatchesDirectory, total);
            Set<String> ownedGlobalIds = new TreeSet<>();
            Set<String> ownedTypeIds = new TreeSet<>();
            boolean incompleteSeen = false;
            for (int start = 0; start < total; start += PLANNING_BATCH_FUNCTIONS) {
                int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, total);
                ExporterSemanticFingerprintV1.BatchCommitment expectedBatch =
                    expectedPlanningBatch(planningSemanticState, start, end);
                String baseName = planningBatchBaseName(start, end);
                Path functionFragmentPath = planningBatchesDirectory.resolve(baseName + ".functions.fragment");
                Path globalFragmentPath = planningBatchesDirectory.resolve(baseName + ".globals.fragment");
                Path typeFragmentPath = planningBatchesDirectory.resolve(baseName + ".types.fragment");
                Path failureFragmentPath = planningBatchesDirectory.resolve(baseName + ".failures.fragment");
                Path checkpointPath = planningBatchesDirectory.resolve(baseName + ".checkpoint");
                boolean functionFragmentExists = Files.isRegularFile(functionFragmentPath);
                boolean globalFragmentExists = Files.isRegularFile(globalFragmentPath);
                boolean typeFragmentExists = Files.isRegularFile(typeFragmentPath);
                boolean failureFragmentExists = Files.isRegularFile(failureFragmentPath);
                boolean checkpointExists = Files.isRegularFile(checkpointPath);
                boolean allFragmentsExist = functionFragmentExists && globalFragmentExists && typeFragmentExists && failureFragmentExists;
                boolean anyArtifactExists =
                    functionFragmentExists || globalFragmentExists || typeFragmentExists || failureFragmentExists || checkpointExists;
                if (checkpointExists) {
                    if (!allFragmentsExist) {
                        throw new IllegalStateException("planning batch checkpoint has missing evidence fragments: " + baseName);
                    }
                    if (incompleteSeen) {
                        throw new IllegalStateException("planning batch checkpoints are not a contiguous prefix");
                    }
                    PlanningBatchValidation validation = validatePlanningBatchPair(
                        functionFragmentPath,
                        globalFragmentPath,
                        typeFragmentPath,
                        failureFragmentPath,
                        checkpointPath,
                        start,
                        end,
                        functionIds.subList(start, end),
                        stateSha256,
                        inventorySha256
                    );
                    requirePlanningBatchMatchesSemanticState(expectedBatch, validation);
                    for (String id : validation.globals.ids) {
                        if (!ownedGlobalIds.add(id)) {
                            throw new IllegalStateException("global evidence is owned by more than one planning batch: " + id);
                        }
                    }
                    for (String id : validation.types.ids) {
                        if (!ownedTypeIds.add(id)) {
                            throw new IllegalStateException("type evidence is owned by more than one planning batch: " + id);
                        }
                    }
                    functionRecords.add(new BoundFragment(
                        functionFragmentPath,
                        validation.functions.fragmentBytes,
                        validation.functions.fragmentSha256,
                        functionIds.subList(start, end)
                    ));
                    BoundFragment globalBinding = new BoundFragment(
                        globalFragmentPath,
                        validation.globals.fragmentBytes,
                        validation.globals.fragmentSha256,
                        validation.globals.ids
                    );
                    BoundFragment typeBinding = new BoundFragment(
                        typeFragmentPath,
                        validation.types.fragmentBytes,
                        validation.types.fragmentSha256,
                        validation.types.ids
                    );
                    if (validation.globals.ids.isEmpty()) auxiliaryEvidence.add(globalBinding); else globalRecords.add(globalBinding);
                    if (validation.types.ids.isEmpty()) auxiliaryEvidence.add(typeBinding); else typeRecords.add(typeBinding);
                    auxiliaryEvidence.add(new BoundFragment(
                        failureFragmentPath,
                        validation.failures.fragmentBytes,
                        validation.failures.fragmentSha256,
                        validation.failures.ids
                    ));
                    auxiliaryEvidence.add(bindCurrentFile(checkpointPath, new ArrayList<>()));
                    completed = end;
                    recovered += validation.functions.recovered;
                    partial += validation.functions.partial;
                    failed += validation.functions.failed;
                } else {
                    if (anyArtifactExists && incompleteSeen) {
                        throw new IllegalStateException("only the first incomplete planning batch may have orphan fragments");
                    }
                    incompleteSeen = true;
                }
            }
            reused = completed;
            observedProgress(progressPath, "planning", completed, total, recovered, partial, failed, reused, null);

            for (int start = completed; start < total; start += PLANNING_BATCH_FUNCTIONS) {
                int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, total);
                ExporterSemanticFingerprintV1.BatchCommitment expectedBatch =
                    expectedPlanningBatch(planningSemanticState, start, end);
                List<String> batchFunctionIds = functionIds.subList(start, end);
                StringBuilder functionFragment = new StringBuilder();
                long functionFragmentBytes = 0;
                PlanningBatchEvidence planningEvidence = new PlanningBatchEvidence(ownedGlobalIds, ownedTypeIds);
                int batchRecovered = 0;
                int batchPartial = 0;
                int batchFailed = 0;
                for (int index = start; index < end; index++) {
                    if (monitor.isCancelled()) throw new InterruptedException("program-model export was cancelled");
                    String id = functionIds.get(index);
                    FunctionExport exported = exportFunction(
                        functions.get(index),
                        null,
                        globalsDirectory,
                        typesDirectory,
                        planningEvidence,
                        false,
                        DECOMPILE_TIMEOUT_SECONDS
                    );
                    if (exported.failure != null) {
                        planningEvidence.retainFailure(id, renderFunctionFailure(id, exported));
                    }
                    functionFragmentBytes = appendBoundedPlanningRecord(
                        functionFragment,
                        functionFragmentBytes,
                        exported.record
                    );
                    if (exported.status.equals("recovered")) batchRecovered++;
                    else if (exported.status.equals("partial")) batchPartial++;
                    else batchFailed++;
                }
                String globalFragment = renderPlanningEvidenceFragment(planningEvidence.globals);
                String typeFragment = renderPlanningEvidenceFragment(planningEvidence.types);
                String failureFragment = renderPlanningEvidenceFragment(planningEvidence.failures);
                String baseName = planningBatchBaseName(start, end);
                Path functionFragmentPath = planningBatchesDirectory.resolve(baseName + ".functions.fragment");
                Path globalFragmentPath = planningBatchesDirectory.resolve(baseName + ".globals.fragment");
                Path typeFragmentPath = planningBatchesDirectory.resolve(baseName + ".types.fragment");
                Path failureFragmentPath = planningBatchesDirectory.resolve(baseName + ".failures.fragment");
                Path checkpointPath = planningBatchesDirectory.resolve(baseName + ".checkpoint");
                String functionFragmentText = functionFragment.toString();
                ExporterSemanticFingerprintV1.requireBatchCommitment(
                    expectedBatch,
                    ExporterSemanticFingerprintV1.commitBatch(
                        start,
                        end,
                        functionFragmentText,
                        globalFragment,
                        typeFragment,
                        failureFragment
                    )
                );
                writePlanningAtomic(functionFragmentPath, functionFragmentText);
                writePlanningAtomic(globalFragmentPath, globalFragment);
                writePlanningAtomic(typeFragmentPath, typeFragment);
                writePlanningAtomic(failureFragmentPath, failureFragment);
                PlanningBatchValidation validation = validatePlanningBatchFragments(
                    functionFragmentPath,
                    globalFragmentPath,
                    typeFragmentPath,
                    failureFragmentPath,
                    batchFunctionIds
                );
                requirePlanningBatchMatchesSemanticState(expectedBatch, validation);
                if (
                    validation.functions.recovered != batchRecovered || validation.functions.partial != batchPartial ||
                    validation.functions.failed != batchFailed ||
                    !validation.globals.ids.equals(new ArrayList<>(planningEvidence.globals.keySet())) ||
                    !validation.types.ids.equals(new ArrayList<>(planningEvidence.types.keySet())) ||
                    !validation.failures.ids.equals(new ArrayList<>(planningEvidence.failures.keySet()))
                ) {
                    throw new IllegalStateException("planning batch evidence changed during durable serialization");
                }
                String checkpoint = renderPlanningBatchCheckpoint(
                    start,
                    end,
                    batchFunctionIds,
                    stateSha256,
                    inventorySha256,
                    validation
                );
                if (checkpoint.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES) {
                    throw new IllegalStateException("planning batch checkpoint exceeds its byte bound: " + baseName);
                }
                writePlanningAtomic(checkpointPath, checkpoint);
                validation = validatePlanningBatchPair(
                    functionFragmentPath,
                    globalFragmentPath,
                    typeFragmentPath,
                    failureFragmentPath,
                    checkpointPath,
                    start,
                    end,
                    batchFunctionIds,
                    stateSha256,
                    inventorySha256
                );
                requirePlanningBatchMatchesSemanticState(expectedBatch, validation);
                for (String id : validation.globals.ids) {
                    if (!ownedGlobalIds.add(id)) {
                        throw new IllegalStateException("global evidence is owned by more than one planning batch: " + id);
                    }
                }
                for (String id : validation.types.ids) {
                    if (!ownedTypeIds.add(id)) {
                        throw new IllegalStateException("type evidence is owned by more than one planning batch: " + id);
                    }
                }
                functionRecords.add(new BoundFragment(
                    functionFragmentPath,
                    validation.functions.fragmentBytes,
                    validation.functions.fragmentSha256,
                    batchFunctionIds
                ));
                BoundFragment globalBinding = new BoundFragment(
                    globalFragmentPath,
                    validation.globals.fragmentBytes,
                    validation.globals.fragmentSha256,
                    validation.globals.ids
                );
                BoundFragment typeBinding = new BoundFragment(
                    typeFragmentPath,
                    validation.types.fragmentBytes,
                    validation.types.fragmentSha256,
                    validation.types.ids
                );
                if (validation.globals.ids.isEmpty()) auxiliaryEvidence.add(globalBinding); else globalRecords.add(globalBinding);
                if (validation.types.ids.isEmpty()) auxiliaryEvidence.add(typeBinding); else typeRecords.add(typeBinding);
                auxiliaryEvidence.add(new BoundFragment(
                    failureFragmentPath,
                    validation.failures.fragmentBytes,
                    validation.failures.fragmentSha256,
                    validation.failures.ids
                ));
                auxiliaryEvidence.add(bindCurrentFile(checkpointPath, new ArrayList<>()));
                completed = end;
                recovered += validation.functions.recovered;
                partial += validation.functions.partial;
                failed += validation.functions.failed;
                observedProgress(progressPath, "planning", completed, total, recovered, partial, failed, reused, null);
                println("program-model planning export " + completed + "/" + total + " batch=" + baseName);
                // The contained owner must durably authorize and deliver the requested stop
                // while this child is still live. Only an explicitly bound interrupted run
                // opens this bounded first-checkpoint delivery window.
                if (holdFirstPlanningCheckpoint && completed == PLANNING_BATCH_FUNCTIONS && completed < total) {
                    Thread.sleep(60_000L);
                }
            }
        }

        assembleModel(outputPath, inputSha256, functionRecords, globalRecords, typeRecords, auxiliaryEvidence);
        observedProgress(progressPath, "complete", completed, total, recovered, partial, failed, reused, null);
        println(
            "program-model export complete functions=" + completed + " partial=" + partial +
                " failed=" + failed + " reused=" + reused
        );
    }
}

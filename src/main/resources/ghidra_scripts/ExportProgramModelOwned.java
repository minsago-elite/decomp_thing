/*
 * Versioned generic analyzer entry point. The retained profile-17 ExportProgramModel.java bytes stay
 * immutable for authenticated GCC evidence; this source is selected only by the ordinary owned
 * analyzer route. Its owned candidate argument changes where the validated model is assembled,
 * while arg[3] continues to bind the existing checkpoint/state/progress identity. It grants no
 * additional Ghidra API or process authority.
 */
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
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

// PARALLEL_EXPORT_TEST_BEGIN
/** Only this coordinator prepares metadata and publishes evidence; workers return immutable results. */
/** Bounded diagnostic observations only: elapsed timers are NOT CPU or qualification facts. */
final class ExporterPhaseObservationOwnedV1 {
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

final class ExporterParallelCoordinatorOwnedV1<M, R> implements AutoCloseable {
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

    ExporterParallelCoordinatorOwnedV1(List<Worker<M, R>> workers) {
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
final class ExporterSemanticFingerprintOwnedV1 {
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

    ExporterSemanticFingerprintOwnedV1() throws Exception {
        this(MAXIMUM_CANONICAL_BYTES);
    }

    ExporterSemanticFingerprintOwnedV1(long maximumCanonicalBytes) throws Exception {
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
final class ExporterPureRenderingOwnedV1 {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final Pattern TYPE_NAME_UNSAFE = Pattern.compile("[^A-Za-z0-9_]");

    private ExporterPureRenderingOwnedV1() { }

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

public class ExportProgramModelOwned extends GhidraScript {
    private ExporterPhaseObservationOwnedV1 phaseObservation;
    private int observedCompleted;
    private long phaseBegin(ExporterPhaseObservationOwnedV1.Phase phase) {
        return phaseObservation == null ? 0L : phaseObservation.begin(phase);
    }
    private void phaseEnd(ExporterPhaseObservationOwnedV1.Phase phase, long started) {
        if (phaseObservation != null) phaseObservation.end(phase, started);
    }
    private void emitPhases(boolean terminal, boolean returned) {
        try { if (phaseObservation != null) phaseObservation.emit(this::println, observedCompleted, terminal, returned); }
        catch (Throwable diagnosticFailure) { /* Never replace the primary outcome. */ }
    }

    private static final int EXPORTER_VERSION = 19;
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
        String byteEvidence;
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
        final ExporterSemanticFingerprintOwnedV1.Binding binding;
        final List<ExporterSemanticFingerprintOwnedV1.BatchCommitment> batches;
        final String batchCommitmentSha256;

        PlanningSemanticState(
            ExporterSemanticFingerprintOwnedV1.Binding binding,
            List<ExporterSemanticFingerprintOwnedV1.BatchCommitment> batches,
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
        return ExporterPureRenderingOwnedV1.addressId("fn_", function.getEntryPoint().getOffset());
    }

    private static String globalId(Address address) {
        return ExporterPureRenderingOwnedV1.addressId("global_", address.getOffset());
    }

    private static String hexDigest(byte[] digest) {
        return ExporterPureRenderingOwnedV1.hexDigest(digest);
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
        if (existing != null && existing.equals(bounded)) return existing;
        return existing == null ? bounded : existing + "; " + bounded;
    }

    private static String exceptionMessage(String phase, Exception failure) {
        if (failure instanceof PrototypeRejected) {
            Refusal refusal = ((PrototypeRejected)failure).refusal;
            return phase + " refused: metadataRefusal=" + refusal.code + ";detail=" + refusal.detail;
        }
        String message = failure.getMessage();
        return phase + " failed: " + failure.getClass().getSimpleName() +
            (message == null || message.trim().isEmpty() ? "" : ": " + message);
    }

    private void rethrowInfrastructureFailure(Exception failure) throws Exception {
        if (failure instanceof InterruptedException) {
            Thread.currentThread().interrupt();
            throw failure;
        }
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
        Address sourceAddress,
        boolean catalogOnly
    ) throws Exception {
        if (!(type instanceof Composite) && !(type instanceof Enum) && !(type instanceof TypeDef)) return;
        String key = type.getPathName();
        String id = typeId(key);
        int length = Math.max(type.getLength(), 1);
        String cName = ExporterPureRenderingOwnedV1.typeName(type.getName());
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
        if (catalogOnly) return; // Preserve metadata/render refusals during replay without filesystem effects.
        if (planningEvidence == null) {
            writeIfAbsentAtomic(typesDirectory.resolve(id + ".json"), record, phaseObservation, true);
        } else {
            planningEvidence.retainType(id, record);
        }
    }

    private static final int MAXIMUM_REFERENCE_CANDIDATES = 65536;
    private static final int MAXIMUM_BYTE_WINDOWS = 4096;
    private static final int MAXIMUM_WINDOWS_PER_GLOBAL = 32;
    private static final int MAXIMUM_WINDOW_BYTES = 256;
    private static final long MAXIMUM_REQUESTED_BYTES = 65536;
    private final Map<String, String> referencedByteEvidence = new TreeMap<>();
    // Set only by the collector's first genuinely unadmitted batch/window, never by a lookup miss.
    private String referenceCollectionCutoff;

    private static final class GlobalByteWindows {
        final List<ByteWindow> windows = new ArrayList<>();
        boolean globalLimit;
    }

    private static final class ByteSortCancelled extends RuntimeException {}

    private String byteAddress(Address address) {
        if (!address.isMemoryAddress() || address.getAddressSpace().getSize() > 64 ||
            !address.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            throw new PlanningIntegrityException("unrepresentable reference byte-evidence address");
        }
        return String.format("0x%x", address.getOffset());
    }

    private void checkByteCancellation() throws Exception {
        if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("reference byte-evidence export was cancelled");
        }
    }

    private static final class ByteWindow {
        final Address target, instruction;
        final int operand, width;
        final String basis, record;
        ByteWindow(Address target, Address instruction, int operand, int width, String basis, String record) {
            this.target = target; this.instruction = instruction; this.operand = operand;
            this.width = width; this.basis = basis; this.record = record;
        }
    }

    private boolean referencesMemory(Varnode value, Address target) {
        return value != null && value.getAddress().isMemoryAddress() && value.getAddress().equals(target);
    }

    // Finite direct-value read policy: binary floating add/multiply consume both inputs.
    // Other arithmetic/control-flow operations remain unsupported until separately reviewed.
    private boolean supportsDirectValueRead(int opcode) {
        return opcode == PcodeOp.FLOAT_ADD || opcode == PcodeOp.FLOAT_MULT;
    }

    // Width comes only from an exact LOAD/STORE pointer or a supported direct RAM value.
    // Control-flow addresses, unsupported operations, dynamic pointers and multiple associations stay unknown.
    private int[] referenceWidth(Instruction instruction, Reference reference) {
        int width = 0, basis = 0, matches = 0;
        Address target = reference.getToAddress();
        for (PcodeOp operation : instruction.getPcode()) {
            int opcode = operation.getOpcode();
            if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                Varnode pointer = operation.getInput(1);
                Varnode space = operation.getInput(0);
                if (!pointer.isConstant() || !space.isConstant()) return new int[] {0, 0};
                if (space.getOffset() != target.getAddressSpace().getSpaceID() || pointer.getOffset() != target.getOffset()) continue;
                matches++;
                width = opcode == PcodeOp.LOAD ? operation.getOutput().getSize() : operation.getInput(2).getSize();
                basis = opcode == PcodeOp.LOAD ? 1 : 2;
            } else if (opcode == PcodeOp.COPY && operation.getNumInputs() == 1 && operation.getOutput() != null) {
                Varnode input = operation.getInput(0), output = operation.getOutput();
                if (referencesMemory(input, target)) { matches++; width = input.getSize(); basis = 3; }
                if (referencesMemory(output, target)) { matches++; width = output.getSize(); basis = 4; }
                if (input.getSize() != output.getSize()) return new int[] {0, 0};
            } else if (supportsDirectValueRead(opcode) && operation.getNumInputs() == 2 && operation.getOutput() != null) {
                Varnode output = operation.getOutput();
                if (referencesMemory(output, target)) return new int[] {0, 0};
                for (Varnode input : operation.getInputs()) {
                    if (input.getSize() != output.getSize()) return new int[] {0, 0};
                    if (referencesMemory(input, target)) { matches++; width = input.getSize(); basis = 3; }
                }
            } else {
                if (referencesMemory(operation.getOutput(), target)) return new int[] {0, 0};
                for (Varnode input : operation.getInputs()) if (referencesMemory(input, target)) return new int[] {0, 0};
            }
        }
        return matches == 1 && width > 0 ? new int[] {width, basis} : new int[] {0, 0};
    }

    private String readByteSegments(Address target, int width) throws Exception {
        StringBuilder segments = new StringBuilder("[");
        int start = 0;
        String previousReason = null;
        StringBuilder hex = new StringBuilder();
        int available = 0;
        for (int offset = 0; offset <= width; offset++) {
            checkByteCancellation();
            String reason = null;
            int value = -1;
            if (offset < width) {
                Address address = target.addNoWrap(offset);
                MemoryBlock block = currentProgram.getMemory().getBlock(address);
                if (block == null) reason = "unmapped";
                else if (!block.isRead()) reason = "unreadable";
                else if (!block.isInitialized()) reason = "uninitialized";
                else {
                    byte[] one = new byte[1];
                    try {
                        if (currentProgram.getMemory().getBytes(address, one) != 1) reason = "read_failed";
                        else { value = one[0] & 255; available++; }
                    } catch (ghidra.program.model.mem.MemoryAccessException failure) { reason = "read_failed"; }
                }
            }
            if (offset > start && (offset == width || !java.util.Objects.equals(reason, previousReason))) {
                if (start > 0) segments.append(',');
                segments.append("{\"offset\":").append(start).append(",\"length\":").append(offset - start)
                    .append(",\"availability\":").append(json(previousReason == null ? "available" : "unavailable"))
                    .append(",\"hex\":").append(previousReason == null ? json(hex.toString()) : "null")
                    .append(",\"reason\":").append(json(previousReason)).append('}');
                start = offset; hex.setLength(0);
            }
            if (value >= 0) hex.append(String.format("%02x", value));
            previousReason = reason;
        }
        segments.append(']');
        String availability = available == width ? "available" : available == 0 ? "unavailable" : "partial";
        return "\"availability\":" + json(availability) + ",\"segments\":" + segments;
    }

    private void checkByteSortCancellation() {
        if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) throw new ByteSortCancelled();
    }

    // ReferenceIterator is streaming; retain at most the remaining work allowance and inspect
    // one nonretained lookahead. A whole oversized instruction batch is left unadmitted.
    private List<Reference> referenceBatch(Instruction instruction, int remaining) throws Exception {
        return referenceBatch(instruction, remaining, true);
    }
    private List<Reference> referenceBatch(Instruction instruction, int remaining, boolean byteCollection) throws Exception {
        List<Reference> batch = new ArrayList<>();
        ReferenceIterator references = currentProgram.getReferenceManager().getReferenceIterator(instruction.getAddress());
        while (references.hasNext()) {
            checkByteCancellation();
            Reference reference = references.next();
            if (!reference.getFromAddress().equals(instruction.getAddress())) break;
            if (batch.size() == remaining) {
                if (byteCollection) referenceCollectionCutoff = "reference_work_limit";
                return null;
            }
            batch.add(reference);
        }
        checkByteCancellation();
        try {
            batch.sort((left, right) -> {
                checkByteSortCancellation();
                int order = left.getToAddress().compareTo(right.getToAddress());
                if (order == 0) order = Integer.compare(Math.max(-1, left.getOperandIndex()), Math.max(-1, right.getOperandIndex()));
                if (order == 0) order = Byte.compare(left.getReferenceType().getValue(), right.getReferenceType().getValue());
                return order;
            });
        } catch (ByteSortCancelled cancelled) {
            throw new InterruptedException("reference byte-evidence export was cancelled");
        }
        checkByteCancellation();
        return batch;
    }

    private String renderByteEvidence(GlobalByteWindows global) throws Exception {
        checkByteCancellation();
        StringBuilder records = new StringBuilder();
        boolean unknown = false;
        if (global != null) {
            try {
                global.windows.sort((left, right) -> {
                    checkByteSortCancellation();
                    int order = left.target.compareTo(right.target);
                    if (order == 0) order = left.instruction.compareTo(right.instruction);
                    if (order == 0) order = Integer.compare(left.operand, right.operand);
                    if (order == 0) order = left.basis.compareTo(right.basis);
                    if (order == 0) order = Integer.compare(left.width, right.width);
                    return order;
                });
            } catch (ByteSortCancelled cancelled) {
                throw new InterruptedException("reference byte-evidence export was cancelled");
            }
            for (ByteWindow window : global.windows) {
                checkByteCancellation();
                unknown |= window.width == 0;
                if (records.length() > 0) records.append(',');
                records.append(window.record);
            }
        }
        String local = global != null && global.globalLimit ? json("global_window_limit") : "";
        String cutoff = referenceCollectionCutoff == null ? "" : json(referenceCollectionCutoff);
        checkByteCancellation();
        return "{\"schemaVersion\":2,\"windows\":[" + records +
            "],\"omissionReason\":" + (unknown ? json("unknown_access_width") : "null") +
            ",\"collectionOmissions\":[" + local + (!local.isEmpty() && !cutoff.isEmpty() ? "," : "") + cutoff + "]}";
    }

    private void collectReferencedByteEvidence(List<Function> functions) throws Exception {
        Map<String, GlobalByteWindows> globals = new TreeMap<>();
        int candidates = 0, windowCount = 0;
        long requestedBytes = 0;
        referencedByteEvidence.clear();
        referenceCollectionCutoff = null;
        collection:
        for (Function function : functions) {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                checkByteCancellation();
                Instruction instruction = instructions.next();
                byteAddress(instruction.getAddress());
                List<Reference> batch = referenceBatch(instruction, MAXIMUM_REFERENCE_CANDIDATES - candidates);
                if (batch == null) break collection;
                // Raw memory-reference entries, including duplicates and filtered references, charge work.
                candidates += batch.size();
                for (Reference reference : batch) {
                    checkByteCancellation();
                    if (!dataReference(reference)) continue;
                    Address target = reference.getToAddress();
                    if (!dataTarget(target)) continue;
                    ResolvedData resolved = resolveAddressedData(target);
                    if (resolved.stringValue) continue;
                    Address base = resolved.base;
                    byteAddress(base);
                    String id = globalId(base);
                    GlobalByteWindows global = globals.get(id);
                    int[] association = referenceWidth(instruction, reference);
                    int width = association[0];
                    if (width > MAXIMUM_WINDOW_BYTES) throw new PlanningIntegrityException("reference window requested-byte bound exceeded");
                    if (width > 0) target.addNoWrap(width - 1L);
                    String basis = association[1] == 1 ? "pcode_load" : association[1] == 2 ? "pcode_store" : association[1] == 3 ? "pcode_direct_read" : association[1] == 4 ? "pcode_direct_write" : "unknown_width";
                    int operand = Math.max(-1, reference.getOperandIndex());
                    boolean duplicate = false;
                    if (global != null) {
                        for (ByteWindow retained : global.windows) {
                            checkByteCancellation();
                            if (retained.target.equals(target) && retained.instruction.equals(instruction.getAddress()) && retained.operand == operand) {
                                if (retained.width != width || !retained.basis.equals(basis))
                                    throw new PlanningIntegrityException("conflicting reference byte-evidence origin: " + id);
                                duplicate = true;
                                break;
                            }
                        }
                    }
                    if (duplicate) continue;
                    if (global != null && global.windows.size() == MAXIMUM_WINDOWS_PER_GLOBAL) {
                        global.globalLimit = true;
                        continue;
                    }
                    if (windowCount == MAXIMUM_BYTE_WINDOWS) {
                        referenceCollectionCutoff = "model_window_limit";
                        break collection;
                    }
                    if (width > MAXIMUM_REQUESTED_BYTES - requestedBytes) {
                        referenceCollectionCutoff = "model_requested_byte_limit";
                        break collection;
                    }
                    String origin = "{\"instructionAddress\":" + json(byteAddress(instruction.getAddress())) +
                        ",\"referenceAddress\":" + json(byteAddress(target)) + ",\"operandIndex\":" +
                        (operand < 0 ? "null" : operand) + ",\"widthBasis\":" + json(basis) + "}";
                    String record = "{\"address\":" + json(byteAddress(target)) + ",\"requestedLength\":" +
                        (width == 0 ? "null" : width) + ",\"origin\":" + origin + "," +
                        (width == 0 ? "\"availability\":\"unknown\",\"segments\":[]" : readByteSegments(target, width)) + "}";
                    if (global == null) {
                        global = new GlobalByteWindows();
                        globals.put(id, global);
                    }
                    global.windows.add(new ByteWindow(target, instruction.getAddress(), operand, width, basis, record));
                    windowCount++;
                    requestedBytes += width;
                }
            }
        }
        checkByteCancellation();
        for (Map.Entry<String, GlobalByteWindows> entry : globals.entrySet()) {
            checkByteCancellation();
            referencedByteEvidence.put(entry.getKey(), renderByteEvidence(entry.getValue()));
        }
        checkByteCancellation();
    }

    enum ResolutionKind { ABSENT, PRIMITIVE, ORIGINAL_CONTAINER }
    static final class ResolvedData {
        final Data selected;
        final Address base;
        final boolean stringValue;
        final ResolutionKind kind;
        ResolvedData(Data selected, Address base, ResolutionKind kind) {
            this.selected = selected; this.base = base; this.kind = kind;
            stringValue = selected != null && selected.hasStringValue() && selected.getValue() != null;
        }
    }
    private static boolean dataReference(Reference reference) {
        return reference.getReferenceType().isData() || reference.getReferenceType().isIndirect();
    }
    private boolean dataTarget(Address target) {
        return target.isMemoryAddress() &&
            currentProgram.getFunctionManager().getFunctionContaining(target) == null &&
            currentProgram.getListing().getInstructionContaining(target) == null;
    }
    private ResolvedData resolveAddressedData(Address target) throws Exception {
        checkByteCancellation();
        byteAddress(target);
        Data original = currentProgram.getListing().getDataContaining(target);
        if (original == null) return new ResolvedData(null, target, ResolutionKind.ABSENT);
        byteAddress(original.getAddress());
        ResolvedData fallback = new ResolvedData(original, original.getAddress(), ResolutionKind.ORIGINAL_CONTAINER);
        if (fallback.stringValue) return fallback;
        Data data = original;
        java.util.IdentityHashMap<Data, Boolean> seen = new java.util.IdentityHashMap<>();
        for (int depth = 0; depth <= 32; depth++) {
            checkByteCancellation();
            if (data == null || seen.put(data, Boolean.TRUE) != null || !data.isDefined() || data.getLength() <= 0)
                return fallback;
            Address start = data.getAddress();
            if (start == null || !start.getAddressSpace().equals(target.getAddressSpace())) return fallback;
            long relative = target.subtract(start);
            if (relative < 0 || relative >= data.getLength()) return fallback;
            if (data.hasStringValue() && data.getValue() != null)
                return new ResolvedData(data, start, ResolutionKind.ORIGINAL_CONTAINER);
            DataType baseType = data.getBaseDataType();
            if (baseType == null || baseType instanceof Union || baseType instanceof Dynamic ||
                baseType instanceof BitFieldDataType || baseType instanceof Undefined || baseType.getLength() <= 0 ||
                baseType.getLength() != data.getLength()) return fallback;
            if (!(baseType instanceof Structure) && !(baseType instanceof Array)) {
                if (relative == 0 && data.getNumComponents() == 0 &&
                    (baseType instanceof Pointer || baseType instanceof Enum || baseType instanceof AbstractIntegerDataType ||
                     baseType instanceof AbstractFloatDataType))
                    return new ResolvedData(data, start, ResolutionKind.PRIMITIVE);
                return fallback;
            }
            if (depth == 32) return fallback;
            int offset = (int)relative;
            Data next;
            int expectedOffset, expectedLength;
            if (baseType instanceof Structure) {
                Structure structure = (Structure)baseType;
                if (structure.getNumComponents() <= 0 || structure.getNumComponents() > 4096) return fallback;
                List<DataTypeComponent> components = structure.getComponentsContaining(offset);
                if (components == null || components.size() != 1) return fallback;
                DataTypeComponent component = components.get(0);
                if (component == null || component.isBitFieldComponent() || component.getLength() <= 0 ||
                    component.getOffset() < 0 || component.getDataType() == null || component.getDataType() instanceof Undefined)
                    return fallback;
                expectedOffset = component.getOffset(); expectedLength = component.getLength();
                next = data.getComponent(component.getOrdinal());
            } else {
                Array array = (Array)baseType;
                int elementLength = array.getElementLength();
                if (elementLength <= 0 || array.getNumElements() <= 0 ||
                    (long)elementLength * array.getNumElements() != data.getLength()) return fallback;
                int index = offset / elementLength;
                expectedOffset = index * elementLength; expectedLength = elementLength;
                next = data.getComponent(index);
            }
            if (next == null || next == data || next.getAddress() == null ||
                !next.getAddress().getAddressSpace().equals(start.getAddressSpace()) ||
                next.getAddress().subtract(start) != expectedOffset || next.getLength() != expectedLength ||
                (long)expectedOffset + expectedLength > data.getLength() ||
                offset < expectedOffset || offset - expectedOffset >= expectedLength) return fallback;
            data = next;
        }
        return fallback;
    }

    // Kept as a probe boundary; all production consumers pass the same resolved selection.
    private GlobalEvidence globalAt(Address address) throws Exception { return globalAt(resolveAddressedData(address)); }
    private GlobalEvidence globalAt(ResolvedData resolved) throws Exception {
        checkByteCancellation();
        Data data = resolved.selected;
        Address base = resolved.base;
        byteAddress(base);
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(base);
        String name = symbol == null ? "DAT_" + base.toString() : symbol.getName();
        String type = data == null ? "unsigned char" : data.getDataType().getDisplayName();
        String initializer = data == null ? null : data.getDefaultValueRepresentation();
        GlobalEvidence global = new GlobalEvidence(globalId(base), name, base, type, initializer);
        global.byteEvidence = referencedByteEvidence.get(global.id);
        if (global.byteEvidence == null && referenceCollectionCutoff != null) global.byteEvidence = renderByteEvidence(null);
        if (global.byteEvidence == null) throw new PlanningIntegrityException("missing reference byte-evidence origin: " + global.id);
        checkByteCancellation();
        return global;
    }

    // OWNED_PROTOTYPE_VALUES_TEST_BEGIN
    enum PrototypeOrigin { LISTING, HIGH_FUNCTION }
    enum PrototypeRefusalCode {
        NO_HIGH_FUNCTION, NULL_SYMBOL, NULL_TYPE, UNSUPPORTED_SHAPE, INVALID_NAME,
        LIMIT, UNPLANNED_TYPE, TYPE_MISMATCH
    }
    static final class Refusal {
        final PrototypeRefusalCode code;
        final String detail;
        Refusal(PrototypeRefusalCode code, String detail) {
            this.code = java.util.Objects.requireNonNull(code);
            this.detail = java.util.Objects.requireNonNull(detail);
            if (!detail.matches("[A-Z0-9_]{1,80}")) throw new IllegalArgumentException("unstable refusal detail");
        }
        String evidence() { return "prototypeSource=listing;prototypeRefusal=" + code + ";detail=" + detail; }
    }
    @SuppressWarnings("serial") // Internal control flow only; the immutable refusal DTO is never serialized.
    static final class PrototypeRejected extends Exception {
        private static final long serialVersionUID = 1L;
        final Refusal refusal;
        PrototypeRejected(PrototypeRefusalCode code, String detail) { refusal = new Refusal(code, detail); }
    }
    static final class PrototypeBudget {
        int nodes, bytes;
        void node(int depth) throws PrototypeRejected {
            if (depth > 32 || ++nodes > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "TYPE_GRAPH");
        }
        String text(String value) throws PrototypeRejected {
            if (value == null) throw new PrototypeRejected(PrototypeRefusalCode.NULL_TYPE, "NULL_TEXT");
            // Check UTF-16 length first so encoding a malformed giant value cannot allocate unboundedly.
            if (value.length() > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "FIELD_BYTES");
            int size = value.getBytes(StandardCharsets.UTF_8).length;
            if (size > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "FIELD_BYTES");
            total(size);
            return value;
        }
        void total(int size) throws PrototypeRejected {
            if (size < 0 || size > 65536 - bytes) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "TOTAL_BYTES");
            bytes += size;
        }
        void parameters(int count, boolean variadic) throws PrototypeRejected {
            if (count < 0 || count > 256) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "PARAMETER_COUNT");
            if (variadic && count == 0) throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "VARARGS_WITHOUT_FIXED_PARAMETER");
        }
    }
    static final class TypeRequirement {
        final String path, id, cSpelling, definitionDigest;
        TypeRequirement(String path, String id, String cSpelling, String definitionDigest) {
            this.path = java.util.Objects.requireNonNull(path);
            this.id = java.util.Objects.requireNonNull(id);
            this.cSpelling = java.util.Objects.requireNonNull(cSpelling);
            this.definitionDigest = java.util.Objects.requireNonNull(definitionDigest);
        }
        boolean same(TypeRequirement other) {
            return id.equals(other.id) && path.equals(other.path) && cSpelling.equals(other.cSpelling) &&
                definitionDigest.equals(other.definitionDigest);
        }
    }
    static final class PlannedTypeCoverage {
        final Map<String, TypeRequirement> byPath;
        final Map<String, String> bySpelling;
        PlannedTypeCoverage(Map<String, TypeRequirement> requirements) {
            byPath = java.util.Collections.unmodifiableMap(new TreeMap<>(requirements));
            Map<String, String> spellings = new TreeMap<>();
            for (TypeRequirement requirement : byPath.values()) {
                String previous = spellings.putIfAbsent(requirement.cSpelling, requirement.path);
                if (previous != null && !previous.equals(requirement.path)) spellings.put(requirement.cSpelling, "");
            }
            bySpelling = java.util.Collections.unmodifiableMap(spellings);
        }
    }
    @FunctionalInterface
    interface PrototypeCancellation { void check() throws InterruptedException; }
    private static final class PrototypeSortCancelled extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final InterruptedException interruption;
        PrototypeSortCancelled(InterruptedException interruption) { this.interruption = interruption; }
    }
    static String[] boundedEnumNames(String[] names, int count, int depth, PrototypeBudget budget,
                                      PrototypeCancellation cancellation) throws Exception {
        cancellation.check();
        if (count < 0 || count > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "ENUM_VALUES");
        if (names == null || names.length != count)
            throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "ENUM_VALUES");
        // Charge every input before copying or comparing any names. Each comparison is now bounded.
        for (String name : names) {
            cancellation.check();
            budget.node(depth + 1);
            budget.text(name);
        }
        cancellation.check();
        String[] sorted = names.clone();
        try {
            java.util.Arrays.sort(sorted, (left, right) -> {
                try { cancellation.check(); }
                catch (InterruptedException interruption) { throw new PrototypeSortCancelled(interruption); }
                return left.compareTo(right);
            });
        } catch (PrototypeSortCancelled cancelled) { throw cancelled.interruption; }
        cancellation.check();
        return sorted;
    }
    static final class PlannedTypeCatalog {
        final Map<String, TypeRequirement> definitions = new TreeMap<>();
        final Map<String, String> spellings = new TreeMap<>();
        void clear() { definitions.clear(); spellings.clear(); }
        void admit(Map<String, TypeRequirement> requirements, PrototypeCancellation cancellation) throws Exception {
            Map<String, String> incomingSpellings = new TreeMap<>();
            int additions = 0;
            for (TypeRequirement requirement : requirements.values()) {
                cancellation.check();
                String previous = incomingSpellings.putIfAbsent(requirement.cSpelling, requirement.path);
                String published = spellings.get(requirement.cSpelling);
                TypeRequirement known = definitions.get(requirement.path);
                if ((previous != null && !previous.equals(requirement.path)) ||
                    (published != null && !published.equals(requirement.path)))
                    throw new PrototypeRejected(PrototypeRefusalCode.TYPE_MISMATCH, "C_SPELLING_COLLISION");
                if (known != null && !known.same(requirement))
                    throw new PrototypeRejected(PrototypeRefusalCode.TYPE_MISMATCH, "NAMED_TYPE_CHANGED");
                if (known == null) additions++;
            }
            if (additions > 4096 - definitions.size())
                throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "PLANNED_NAMED_TYPES");
            cancellation.check();
            // No partial admission on rejection. Existing paths are not charged twice on replay/retry.
            for (TypeRequirement requirement : requirements.values()) {
                definitions.putIfAbsent(requirement.path, requirement);
                spellings.putIfAbsent(requirement.cSpelling, requirement.path);
            }
        }
    }
    static boolean supportedBuiltinSpelling(String spelling) {
        // These are C language spellings, not Ghidra identifiers requiring an invented typedef.
        return java.util.Set.of("void", "char", "signed char", "unsigned char", "short", "short int",
            "signed short", "signed short int", "unsigned short", "unsigned short int", "int", "signed",
            "signed int", "unsigned", "unsigned int", "long", "long int", "signed long", "signed long int",
            "unsigned long", "unsigned long int", "long long", "long long int", "signed long long",
            "signed long long int", "unsigned long long", "unsigned long long int", "float", "double",
            "long double", "_Bool").contains(spelling);
    }
    static final class ParameterText {
        final String name, typeText;
        ParameterText(String name, String typeText) {
            this.name = java.util.Objects.requireNonNull(name);
            this.typeText = java.util.Objects.requireNonNull(typeText);
        }
    }
    static final class TypedPrototype {
        final String declaration, returnText;
        final List<ParameterText> parameters;
        final boolean variadic;
        final List<TypeRequirement> requirements;
        TypedPrototype(String declaration, List<ParameterText> parameters, String returnText,
                       boolean variadic, List<TypeRequirement> requirements) {
            this.declaration = java.util.Objects.requireNonNull(declaration);
            this.parameters = java.util.Collections.unmodifiableList(new ArrayList<>(parameters));
            this.returnText = java.util.Objects.requireNonNull(returnText);
            this.variadic = variadic;
            List<TypeRequirement> sorted = new ArrayList<>(requirements);
            sorted.sort(Comparator.comparing(requirement -> requirement.path));
            this.requirements = java.util.Collections.unmodifiableList(sorted);
        }
    }
    static final class PrototypeResult {
        final TypedPrototype typed;
        final Refusal refusal;
        final PrototypeOrigin origin;
        PrototypeResult(TypedPrototype typed, Refusal refusal) {
            if ((typed == null) == (refusal == null)) throw new IllegalArgumentException("exclusive prototype result required");
            this.typed = typed;
            this.refusal = refusal;
            origin = typed == null ? PrototypeOrigin.LISTING : PrototypeOrigin.HIGH_FUNCTION;
        }
    }
    static final class NativeOutcome {
        final String source, nativeFailure;
        final PrototypeResult prototype;
        NativeOutcome(String source, String nativeFailure, PrototypeResult prototype) {
            this.source = source;
            this.nativeFailure = nativeFailure;
            this.prototype = java.util.Objects.requireNonNull(prototype);
        }
    }
    static Refusal checkCoverage(TypedPrototype typed, PlannedTypeCoverage planned) {
        Map<String, TypeRequirement> seen = new TreeMap<>();
        Map<String, String> spellings = new TreeMap<>();
        for (TypeRequirement requirement : typed.requirements) {
            TypeRequirement previous = seen.putIfAbsent(requirement.path, requirement);
            String previousPath = spellings.putIfAbsent(requirement.cSpelling, requirement.path);
            if ((previous != null && !previous.same(requirement)) ||
                (previousPath != null && !previousPath.equals(requirement.path)))
                return new Refusal(PrototypeRefusalCode.TYPE_MISMATCH, "CONFLICTING_REQUIREMENTS");
            TypeRequirement known = planned.byPath.get(requirement.path);
            if (known == null) return new Refusal(PrototypeRefusalCode.UNPLANNED_TYPE, "NAMED_TYPE_NOT_PLANNED");
            if (!known.same(requirement)) return new Refusal(PrototypeRefusalCode.TYPE_MISMATCH, "NAMED_TYPE_CHANGED");
            if (!requirement.path.equals(planned.bySpelling.get(requirement.cSpelling)))
                return new Refusal(PrototypeRefusalCode.TYPE_MISMATCH, "C_SPELLING_COLLISION");
        }
        return null;
    }
    static boolean validCName(String name) {
        if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_]*")) return false;
        return !(" auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local ")
            .contains(" " + name + " ");
    }
    static String prototypeStatus(boolean full, String source, boolean metadataComplete, Refusal refusal) {
        if (!full) return metadataComplete ? "partial" : "failed";
        return source == null ? "failed" : metadataComplete && refusal == null ? "recovered" : "partial";
    }
    // OWNED_PROTOTYPE_VALUES_TEST_END

    private static final class FunctionMetadata {
        final Function function;
        final String identity, name, listingPrototype, evidence, failure;
        final boolean evidenceComplete;
        final PlannedTypeCoverage coverage;
        FunctionMetadata(Function function, String identity, String name, String listingPrototype, String evidence,
                         String failure, boolean evidenceComplete, PlannedTypeCoverage coverage) {
            this.function = function;
            this.identity = identity;
            this.name = name;
            this.listingPrototype = listingPrototype;
            this.evidence = evidence;
            this.failure = failure;
            this.evidenceComplete = evidenceComplete;
            this.coverage = coverage;
        }
    }

    private static void prototypeCancellation(TaskMonitor taskMonitor) throws InterruptedException {
        if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted())
            throw new InterruptedException("typed prototype extraction was cancelled");
    }

    /** Lives only during coordinator preparation or a single native call, never in a worker result. */
    private static final class TypedGraph {
        final PrototypeBudget budget = new PrototypeBudget();
        final TaskMonitor taskMonitor;
        final Map<String, DataType> named = new TreeMap<>();
        final java.util.IdentityHashMap<DataType, Boolean> namedInstances = new java.util.IdentityHashMap<>();
        final List<DataType> definitions = new ArrayList<>();
        boolean recording = true;
        final Map<String, TypeRequirement> requirements = new TreeMap<>();
        TypedGraph(TaskMonitor taskMonitor) { this.taskMonitor = taskMonitor; }
        String field(String value) throws PrototypeRejected { return budget.text(value).length() + ":" + value; }
        void append(StringBuilder output, String value) throws PrototypeRejected {
            if (value.length() > 65536 - output.length()) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "DESCRIPTOR_BYTES");
            output.append(value);
        }
        String describe(DataType type, int depth, java.util.IdentityHashMap<DataType, Boolean> active,
                        Map<String, DataType> activeNames) throws Exception {
            prototypeCancellation(taskMonitor);
            budget.node(depth);
            if (type == null) throw new PrototypeRejected(PrototypeRefusalCode.NULL_TYPE, "MISSING_DATA_TYPE");
            boolean isNamed = type instanceof Composite || type instanceof Enum || type instanceof TypeDef;
            String path = type instanceof Pointer ? "<pointer>" : type instanceof Array ? "<array>" : budget.text(type.getPathName());
            if (isNamed && activeNames.containsKey(path)) {
                if (activeNames.get(path) != type) throw new PrototypeRejected(PrototypeRefusalCode.TYPE_MISMATCH, "RECURSIVE_PATH_CONFLICT");
                return "ref:" + field(path);
            }
            if (active.put(type, Boolean.TRUE) != null)
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "WRAPPER_CYCLE");
            if (isNamed) activeNames.put(path, type);
            String kind = type instanceof TypeDef ? "typedef" : type instanceof Pointer ? "pointer" :
                type instanceof Array ? "array" : type instanceof Structure ? "struct" :
                type instanceof Union ? "union" : type instanceof Enum ? "enum" :
                type instanceof VoidDataType ? "void" : type instanceof AbstractIntegerDataType ? "integer" :
                type instanceof AbstractFloatDataType ? "float" : (type instanceof Undefined || type instanceof DefaultDataType) ? "undefined" : "unsupported";
            if (kind.equals("unsupported") || type instanceof Dynamic || type instanceof BitFieldDataType)
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "TYPE_CONSTRUCTOR");
            if ((isNamed || type instanceof Pointer || type instanceof Array) && type.getLength() <= 0)
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "UNSIZED_TYPE");
            StringBuilder descriptor = new StringBuilder(kind + ";" + field(path) + ";" + type.getLength() + ";");
            if (isNamed) {
                String name = budget.text(type.getName());
                if (!validCName(name)) throw new PrototypeRejected(PrototypeRefusalCode.INVALID_NAME, "TYPE_NAME");
                if (recording) {
                    named.putIfAbsent(path, type);
                    if (namedInstances.put(type, Boolean.TRUE) == null) definitions.add(type);
                }
            }
            if (type instanceof Pointer) {
                append(descriptor, describe(((Pointer)type).getDataType(), depth + 1, active, activeNames));
            } else if (type instanceof TypeDef) {
                append(descriptor, describe(((TypeDef)type).getDataType(), depth + 1, active, activeNames));
            } else if (type instanceof Array) {
                Array array = (Array)type;
                if (array.getNumElements() <= 0 || array.getElementLength() <= 0 ||
                    (long)array.getNumElements() * array.getElementLength() != array.getLength())
                    throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "UNSIZED_ARRAY");
                append(descriptor, array.getNumElements() + ";" + array.getElementLength() + ";");
                append(descriptor, describe(array.getDataType(), depth + 1, active, activeNames));
            } else if (type instanceof Composite) {
                Composite aggregate = (Composite)type;
                int count = aggregate.getNumComponents();
                if (count < 0 || count > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "AGGREGATE_FIELDS");
                for (int i = 0; i < count; i++) {
                    prototypeCancellation(taskMonitor);
                    DataTypeComponent component = aggregate.getComponent(i);
                    if (component == null || component.isBitFieldComponent() || component.getLength() <= 0 || component.getOffset() < 0 ||
                        (long)component.getOffset() + component.getLength() > aggregate.getLength())
                        throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "AGGREGATE_COMPONENT");
                    append(descriptor, i + ";" + field(component.getFieldName() == null ? "" : component.getFieldName()) +
                        ";" + component.getOffset() + ";" + component.getLength() + ";");
                    append(descriptor, describe(component.getDataType(), depth + 1, active, activeNames));
                }
            } else if (type instanceof Enum) {
                Enum enumeration = (Enum)type;
                int count = enumeration.getCount();
                if (count < 0 || count > 4096) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "ENUM_VALUES");
                String[] names = boundedEnumNames(enumeration.getNames(), count, depth, budget,
                    () -> prototypeCancellation(taskMonitor));
                for (String name : names) {
                    prototypeCancellation(taskMonitor);
                    // Name text/node costs were charged before sorting; descriptor bytes are charged below.
                    append(descriptor, name.length() + ":" + name + ";" + enumeration.getValue(name) + ";");
                }
            }
            active.remove(type);
            if (isNamed) activeNames.remove(path);
            budget.total(descriptor.toString().getBytes(StandardCharsets.UTF_8).length);
            return descriptor.toString();
        }
        void validate(DataType type) throws Exception {
            describe(type, 0, new java.util.IdentityHashMap<>(), new TreeMap<>());
        }
        void finish() throws Exception {
            // A standalone root for each definition makes its digest independent of discovery order.
            recording = false;
            for (DataType definition : definitions) {
                prototypeCancellation(taskMonitor);
                String descriptor = describe(definition, 0, new java.util.IdentityHashMap<>(), new TreeMap<>());
                String name = budget.text(definition.getName());
                String path = definition.getPathName();
                TypeRequirement requirement = new TypeRequirement(budget.text(path), budget.text(typeId(path)), budget.text(name),
                    budget.text(sha256(descriptor.getBytes(StandardCharsets.UTF_8))));
                TypeRequirement previous = requirements.putIfAbsent(path, requirement);
                if (previous != null && !previous.same(requirement))
                    throw new PrototypeRejected(PrototypeRefusalCode.TYPE_MISMATCH, "NAMED_TYPE_CHANGED");
            }
        }
        String signatureText(DataType type, boolean allowVoid) throws Exception {
            prototypeCancellation(taskMonitor);
            DataType leaf = type;
            int depth = 0;
            while (leaf instanceof Pointer || leaf instanceof TypeDef) {
                prototypeCancellation(taskMonitor);
                if (++depth > 32) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "SIGNATURE_DEPTH");
                if (leaf instanceof Pointer) { allowVoid = true; leaf = ((Pointer)leaf).getDataType(); }
                else leaf = ((TypeDef)leaf).getDataType();
                if (leaf == null) throw new PrototypeRejected(PrototypeRefusalCode.NULL_TYPE, "POINTER_TARGET");
            }
            if (!(leaf instanceof AbstractIntegerDataType) && !(leaf instanceof AbstractFloatDataType) &&
                !(leaf instanceof Composite) && !(leaf instanceof Enum) && !(allowVoid && leaf instanceof VoidDataType))
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "SIGNATURE_CONSTRUCTOR");
            if (!(leaf instanceof VoidDataType) && leaf.getLength() <= 0)
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "UNSIZED_SIGNATURE");
            if ((leaf instanceof AbstractIntegerDataType || leaf instanceof AbstractFloatDataType || leaf instanceof VoidDataType) &&
                !supportedBuiltinSpelling(budget.text(leaf.getDisplayName())))
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "BUILTIN_C_SPELLING");
            String text = budget.text(type.getDisplayName());
            // Validated simple constructors only. This is a spelling guard, never C-signature parsing.
            if (!text.matches("[A-Za-z_][A-Za-z0-9_ ]*(?: *\\* *)*"))
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "TYPE_SPELLING");
            return text;
        }
    }

    private static String typeId(String path) throws Exception { return "type_" + sha256(path.getBytes(StandardCharsets.UTF_8)); }

    static PrototypeResult extractTypedPrototype(DecompileResults result, String functionName, TaskMonitor taskMonitor) throws Exception {
        prototypeCancellation(taskMonitor);
        HighFunction high = result == null ? null : result.getHighFunction();
        prototypeCancellation(taskMonitor);
        FunctionPrototype prototype = high == null ? null : high.getFunctionPrototype();
        prototypeCancellation(taskMonitor);
        if (prototype == null)
            return new PrototypeResult(null, new Refusal(PrototypeRefusalCode.NO_HIGH_FUNCTION, "MISSING_HIGH_PROTOTYPE"));
        return extractTypedPrototype(prototype, functionName, taskMonitor);
    }

    // The typed overload is also the public-API fixture boundary; no listing parameters are accepted.
    static PrototypeResult extractTypedPrototype(FunctionPrototype prototype, String functionName, TaskMonitor taskMonitor) throws Exception {
        prototypeCancellation(taskMonitor);
        try {
            if (prototype == null) return new PrototypeResult(null, new Refusal(PrototypeRefusalCode.NO_HIGH_FUNCTION, "MISSING_HIGH_PROTOTYPE"));
            TypedGraph graph = new TypedGraph(taskMonitor);
            if (functionName == null) throw new PrototypeRejected(PrototypeRefusalCode.INVALID_NAME, "FUNCTION_NAME");
            graph.budget.text(functionName);
            if (!validCName(functionName)) throw new PrototypeRejected(PrototypeRefusalCode.INVALID_NAME, "FUNCTION_NAME");
            int count = prototype.getNumParams();
            boolean variadic = prototype.isVarArg();
            graph.budget.parameters(count, variadic);
            DataType returnType = prototype.getReturnType();
            graph.validate(returnType);
            List<DataType> types = new ArrayList<>();
            List<String> names = new ArrayList<>();
            Set<String> uniqueNames = new TreeSet<>();
            for (int index = 0; index < count; index++) {
                prototypeCancellation(taskMonitor);
                HighSymbol symbol = prototype.getParam(index);
                if (symbol == null) throw new PrototypeRejected(PrototypeRefusalCode.NULL_SYMBOL, "MISSING_HIGH_PARAMETER");
                String name = symbol.getName();
                if (name == null) throw new PrototypeRejected(PrototypeRefusalCode.INVALID_NAME, "MISSING_PARAMETER_NAME");
                graph.budget.text(name);
                if (!validCName(name) || !uniqueNames.add(name)) throw new PrototypeRejected(PrototypeRefusalCode.INVALID_NAME, "PARAMETER_NAME");
                DataType type = symbol.getDataType();
                graph.validate(type);
                names.add(name); types.add(type);
            }
            graph.finish();
            String returnText = graph.signatureText(returnType, true);
            List<ParameterText> parameters = new ArrayList<>();
            StringBuilder expected = new StringBuilder(returnText + " " + functionName + "(");
            for (int index = 0; index < count; index++) {
                prototypeCancellation(taskMonitor);
                String text = graph.signatureText(types.get(index), false);
                parameters.add(new ParameterText(names.get(index), text));
                if (index > 0) expected.append(", ");
                expected.append(text).append(' ').append(names.get(index));
            }
            if (variadic) expected.append(", ...");
            else if (count == 0) expected.append("void");
            expected.append(')');
            graph.budget.text(expected.toString());
            // All graph, string and constructor rejection precedes the first cloning/rendering call.
            prototypeCancellation(taskMonitor);
            FunctionDefinitionDataType definition = new FunctionDefinitionDataType(functionName);
            definition.setReturnType(returnType);
            ParameterDefinition[] arguments = new ParameterDefinition[count];
            for (int index = 0; index < count; index++) {
                prototypeCancellation(taskMonitor);
                arguments[index] = new ParameterDefinitionImpl(names.get(index), types.get(index), null);
            }
            definition.setArguments(arguments);
            definition.setVarArgs(variadic);
            prototypeCancellation(taskMonitor);
            String declaration = definition.getPrototypeString(false);
            prototypeCancellation(taskMonitor);
            if (!expected.toString().equals(declaration))
                throw new PrototypeRejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "RENDERED_SHAPE_CHANGED");
            return new PrototypeResult(new TypedPrototype(declaration, parameters, returnText, variadic,
                new ArrayList<>(graph.requirements.values())), null);
        } catch (PrototypeRejected rejected) {
            prototypeCancellation(taskMonitor);
            return new PrototypeResult(null, rejected.refusal);
        } catch (IllegalArgumentException unsupported) {
            prototypeCancellation(taskMonitor);
            return new PrototypeResult(null, new Refusal(PrototypeRefusalCode.UNSUPPORTED_SHAPE, "TYPED_API_REJECTED"));
        }
    }

    private final PlannedTypeCatalog plannedTypes = new PlannedTypeCatalog();

    private static void mergeCoverage(Map<String, TypeRequirement> coverage, PlannedTypeCoverage additional) throws PrototypeRejected {
        for (TypeRequirement requirement : additional.byPath.values()) {
            TypeRequirement previous = coverage.putIfAbsent(requirement.path, requirement);
            if (previous != null && !previous.same(requirement))
                throw new PrototypeRejected(PrototypeRefusalCode.TYPE_MISMATCH, "NAMED_TYPE_CHANGED");
        }
    }

    private PlannedTypeCoverage planTypeCoverage(List<DataType> roots, Path typesDirectory,
                                                 PlanningBatchEvidence planningEvidence, Address source) throws Exception {
        return planTypeCoverage(roots, typesDirectory, planningEvidence, source, false);
    }

    private PlannedTypeCoverage planTypeCoverage(List<DataType> roots, Path typesDirectory,
                                                 PlanningBatchEvidence planningEvidence, Address source,
                                                 boolean catalogOnly) throws Exception {
        TypedGraph graph = new TypedGraph(monitor);
        for (DataType root : roots) { prototypeCancellation(monitor); graph.validate(root); }
        graph.finish();
        plannedTypes.admit(graph.requirements, () -> prototypeCancellation(monitor));
        for (DataType type : graph.named.values()) retainType(typesDirectory, planningEvidence, type, source, catalogOnly);
        // Only this function's deterministic metadata closure is admitted; future functions cannot enlarge it.
        return new PlannedTypeCoverage(graph.requirements);
    }

    private FunctionMetadata collectFunctionMetadata(
        Function function,
        Path globalsDirectory,
        Path typesDirectory,
        PlanningBatchEvidence planningEvidence
    ) throws Exception {
        return collectFunctionMetadata(function, globalsDirectory, typesDirectory, planningEvidence, false);
    }

    private FunctionMetadata collectFunctionMetadata(Function function, Path globalsDirectory, Path typesDirectory,
                                                       PlanningBatchEvidence planningEvidence, boolean catalogOnly) throws Exception {
        prototypeCancellation(monitor);
        Set<String> callIds = new TreeSet<>();
        Set<String> referencedGlobals = new TreeSet<>();
        Set<String> strings = new TreeSet<>();
        String failure = null;
        boolean evidenceComplete = true;
        Map<String, TypeRequirement> coverage = new TreeMap<>();

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
            int metadataCandidates = 0;
            while (instructions.hasNext()) {
                if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("program-model metadata recovery was cancelled");
                }
                Instruction instruction = instructions.next();
                byteAddress(instruction.getAddress());
                List<Reference> batch = referenceBatch(instruction, MAXIMUM_REFERENCE_CANDIDATES - metadataCandidates, false);
                if (batch == null) {
                    evidenceComplete = false;
                    failure = appendFailure(failure, "metadataRefusal=REFERENCE_WORK_LIMIT");
                    break;
                }
                metadataCandidates += batch.size();
                for (Reference reference : batch) {
                    checkByteCancellation();
                    if (!dataReference(reference)) continue;
                    Address target = reference.getToAddress();
                    if (!dataTarget(target)) continue;
                    ResolvedData resolved = resolveAddressedData(target);
                    Data data = resolved.selected;
                    if (resolved.stringValue) {
                        strings.add(data.getValue().toString());
                        continue;
                    }
                    {
                        GlobalEvidence global = globalAt(resolved);
                        String globalRecord = renderGlobal(global);
                        if (catalogOnly) {
                            // Replay reads the same metadata and charges traversal, but publishes no evidence.
                        } else if (planningEvidence == null) {
                            writeIfAbsentAtomic(globalsDirectory.resolve(global.id + ".json"), globalRecord, phaseObservation, false);
                        } else {
                            planningEvidence.retainGlobal(global.id, globalRecord);
                        }
                        referencedGlobals.add(global.id);
                        if (data != null) {
                            mergeCoverage(coverage, planTypeCoverage(java.util.Collections.singletonList(data.getDataType()),
                                typesDirectory, planningEvidence, global.address, catalogOnly));
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
            List<DataType> signatureTypes = new ArrayList<>();
            signatureTypes.add(function.getReturnType());
            Parameter[] listingParameters = function.getParameters();
            if (listingParameters.length > 256) throw new PrototypeRejected(PrototypeRefusalCode.LIMIT, "PARAMETER_COUNT");
            for (Parameter parameter : listingParameters) {
                prototypeCancellation(monitor);
                signatureTypes.add(parameter.getDataType());
            }
            mergeCoverage(coverage, planTypeCoverage(signatureTypes, typesDirectory, planningEvidence, function.getEntryPoint(), catalogOnly));
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
        String listingPrototype = function.getPrototypeString(false, false);
        StringBuilder evidence = new StringBuilder();
        evidence.append("      \"recoveryAssessment\": \"unassessed\",\n");
        evidence.append("      \"calls\": ["); appendStrings(evidence, callIds); evidence.append("],\n");
        evidence.append("      \"referencedGlobals\": ["); appendStrings(evidence, referencedGlobals); evidence.append("],\n");
        evidence.append("      \"strings\": ["); appendStrings(evidence, strings); evidence.append("],\n");
        if ((long) prefix.length() + evidence.length() + listingPrototype.length() > MAXIMUM_FULL_FUNCTION_RECORD_BYTES ||
            (long) prefix.toString().getBytes(StandardCharsets.UTF_8).length +
                evidence.toString().getBytes(StandardCharsets.UTF_8).length +
                listingPrototype.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_FULL_FUNCTION_RECORD_BYTES) {
            throw new PlanningIntegrityException("function metadata exceeds its byte bound: " + functionId(function));
        }
        return new FunctionMetadata(function, prefix.toString(), function.getName(), listingPrototype, evidence.toString(),
            failure, evidenceComplete, new PlannedTypeCoverage(coverage));
    }

    /** Replay only in address order, interleaved with new preparation for sparse full checkpoints.
     * One bounded metadata closure is discarded per function; no native calls or evidence writes.
     * The same graph/reference/cancellation limits apply, including partially admitted failed metadata.
     */
    private void replayTypeCatalog(List<Function> functions, int start, int end) throws Exception {
        for (int index = start; index < end; index++) {
            prototypeCancellation(monitor);
            collectFunctionMetadata(functions.get(index), null, null, null, true);
        }
    }

    private static NativeOutcome decompileFunction(
        Function function,
        String functionName,
        DecompInterface decompiler,
        int timeoutSeconds,
        TaskMonitor taskMonitor
    ) throws Exception {
        String source = null;
        String failure = null;
        PrototypeResult prototype = new PrototypeResult(null, new Refusal(PrototypeRefusalCode.NO_HIGH_FUNCTION, "NO_NATIVE_RESULT"));
        try {
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("program-model native decompilation was cancelled");
            }
            DecompileResults result = decompiler.decompileFunction(function, timeoutSeconds, taskMonitor);
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("program-model native decompilation was cancelled");
            }
            DecompiledFunction rendered = result != null && result.decompileCompleted() ? result.getDecompiledFunction() : null;
            if (rendered != null) {
                source = rendered.getC();
                if (source == null) failure = appendFailure(failure, "nativeRefusal=NULL_SOURCE");
                if (source != null && (source.length() > MAXIMUM_FULL_FUNCTION_RECORD_BYTES ||
                    source.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_FULL_FUNCTION_RECORD_BYTES)) {
                    throw new PlanningIntegrityException("decompiled source exceeds its byte bound");
                }
            } else {
                String detail = result == null ? null : result.getErrorMessage();
                failure = appendFailure(null, "decompilation failed or timed out" +
                    (detail == null || detail.trim().isEmpty() ? "" : ": " + detail));
            }
            prototype = extractTypedPrototype(result, functionName, taskMonitor);
        } catch (Exception problem) {
            if (taskMonitor.isCancelled() || Thread.currentThread().isInterrupted() ||
                problem instanceof InterruptedException || problem instanceof IOException ||
                problem instanceof PlanningIntegrityException) throw problem;
            failure = appendFailure(failure, exceptionMessage("decompilation", problem));
        }
        prototypeCancellation(taskMonitor);
        return new NativeOutcome(source, failure, prototype);
    }

    private static FunctionExport renderFunction(FunctionMetadata metadata, NativeOutcome nativeOutcome, boolean full) {
        if (full && nativeOutcome == null) throw new IllegalArgumentException("full rendering requires native outcome");
        String source = nativeOutcome == null ? null : nativeOutcome.source;
        String failure = nativeOutcome == null ? metadata.failure : appendFailure(metadata.failure, nativeOutcome.nativeFailure);
        Refusal refusal = nativeOutcome == null ? null : nativeOutcome.prototype.refusal;
        if (full && refusal == null) refusal = checkCoverage(nativeOutcome.prototype.typed, metadata.coverage);
        PrototypeOrigin origin = full && refusal == null ? PrototypeOrigin.HIGH_FUNCTION : PrototypeOrigin.LISTING;
        String prototype = origin == PrototypeOrigin.HIGH_FUNCTION ? nativeOutcome.prototype.typed.declaration : metadata.listingPrototype;
        if (full && refusal != null) failure = appendFailure(failure, refusal.evidence());
        String status = prototypeStatus(full, source, metadata.evidenceComplete, refusal);
        String record = metadata.identity + "      \"prototype\": " + json(prototype) + ",\n" + "      \"extractionStatus\": " + json(status) + ",\n" +
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
            ? decompileFunction(function, metadata.name, decompiler, decompileTimeoutSeconds, monitor) : null;
        return renderFunction(metadata, nativeOutcome, includeDecompiledC);
    }

    private final class NativeWorker implements ExporterParallelCoordinatorOwnedV1.Worker<FunctionMetadata, FunctionExport> {
        private final DecompInterface decompiler;
        private final TaskMonitorAdapter taskMonitor = new TaskMonitorAdapter(true);

        private final int workerIndex;
        private final ExporterPhaseObservationOwnedV1 observation;
        NativeWorker(int workerIndex) { this(workerIndex, new DecompInterface()); }
        NativeWorker(int workerIndex, DecompInterface decompiler) {
            this.decompiler = java.util.Objects.requireNonNull(decompiler);
            this.workerIndex = workerIndex;
            this.observation = phaseObservation;
            try {
                DecompileOptions decompileOptions = new DecompileOptions();
                decompileOptions.setMaxInstructions(MAXIMUM_DECOMPILE_INSTRUCTIONS);
                decompiler.setOptions(decompileOptions);
                if (!decompiler.toggleSyntaxTree(true) || !decompiler.toggleCCode(true)) {
                    throw new IllegalStateException("Ghidra decompiler rejected source/syntax-tree configuration");
                }
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Ghidra decompiler could not open the current program");
                }
            } catch (RuntimeException | Error failure) {
                try { decompiler.stopProcess(); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
                try { decompiler.dispose(); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }

        @Override
        public FunctionExport execute(FunctionMetadata metadata, boolean retry) throws Exception {
            ExporterPhaseObservationOwnedV1.Phase nativePhase = ExporterPhaseObservationOwnedV1.Phase.values()[
                ExporterPhaseObservationOwnedV1.Phase.NATIVE_0_INITIAL.ordinal() + workerIndex * 2 + (retry ? 1 : 0)];
            long started = observation.begin(nativePhase);
            NativeOutcome outcome;
            try { outcome = decompileFunction(metadata.function, metadata.name, decompiler,
                retry ? DECOMPILE_RETRY_TIMEOUT_SECONDS : DECOMPILE_TIMEOUT_SECONDS, taskMonitor); }
            finally { observation.end(nativePhase, started); }
            long rendering = observation.begin(ExporterPhaseObservationOwnedV1.Phase.RENDER);
            try { return renderFunction(metadata, outcome, true); }
            finally { observation.end(ExporterPhaseObservationOwnedV1.Phase.RENDER, rendering); }
        }

        @Override
        public void cancel() {
            taskMonitor.cancel();
            decompiler.stopProcess();
        }

        @Override
        public void dispose() { decompiler.dispose(); }
    }

    private ExporterParallelCoordinatorOwnedV1<FunctionMetadata, FunctionExport> createFullRecoveryCoordinator(int count) {
        List<ExporterParallelCoordinatorOwnedV1.Worker<FunctionMetadata, FunctionExport>> workers = new ArrayList<>();
        try {
            for (int index = 0; index < count; index++) workers.add(new NativeWorker(index));
            return new ExporterParallelCoordinatorOwnedV1<>(workers);
        } catch (RuntimeException | Error failure) {
            for (ExporterParallelCoordinatorOwnedV1.Worker<FunctionMetadata, FunctionExport> worker : workers) {
                try { worker.cancel(); } catch (Throwable problem) { failure.addSuppressed(problem); }
                try { worker.dispose(); } catch (Throwable problem) { failure.addSuppressed(problem); }
            }
            throw failure;
        }
    }

    private PlanningSemanticState computePlanningSemanticState(List<Function> functions) throws Exception {
        plannedTypes.clear();
        ExporterSemanticFingerprintOwnedV1 fingerprint = new ExporterSemanticFingerprintOwnedV1();
        Set<String> ownedGlobalIds = new TreeSet<>();
        Set<String> ownedTypeIds = new TreeSet<>();
        List<ExporterSemanticFingerprintOwnedV1.BatchCommitment> batches = new ArrayList<>();
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
            batches.add(ExporterSemanticFingerprintOwnedV1.commitBatch(
                start,
                end,
                functionFragment.toString(),
                globalFragment,
                typeFragment,
                failureFragment
            ));
        }
        ExporterSemanticFingerprintOwnedV1.Binding binding = fingerprint.finish(functions.size());
        return new PlanningSemanticState(
            binding,
            batches,
            ExporterSemanticFingerprintOwnedV1.batchCommitmentSha256(batches)
        );
    }

    private static String renderGlobal(GlobalEvidence global) {
        return "    {\n" +
            "      \"id\": " + json(global.id) + ",\n" +
            "      \"name\": " + json(global.name) + ",\n" +
            "      \"address\": " + json(String.format("0x%x", global.address.getOffset())) + ",\n" +
            "      \"type\": " + json(global.type) + ",\n" +
            "      \"initializer\": " + json(global.initializer) + ",\n" +
            "      \"byteEvidence\": " + global.byteEvidence + ",\n" +
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

    private static Path fullBindingPath(Path record) { return record.resolveSibling(record.getFileName() + ".binding"); }
    private static String fullBinding(String functionDigest, String failureDigest) {
        return "owned-function-v19\n" + functionDigest + "\n" + failureDigest + "\n";
    }
    private static String currentFullBinding(Path record, Path failure) throws Exception {
        long size = Files.size(record);
        if (size <= 0 || size > MAXIMUM_FULL_FUNCTION_RECORD_BYTES)
            throw new PlanningIntegrityException("full function checkpoint exceeds its byte bound");
        if (Files.exists(failure) && (!Files.isRegularFile(failure) || Files.size(failure) > MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES))
            throw new PlanningIntegrityException("full failure checkpoint exceeds its byte bound");
        return fullBinding(sha256(record), Files.isRegularFile(failure) ? sha256(failure) : "absent");
    }
    private static void requireFullBinding(Path binding, String expected) throws Exception {
        if (!Files.isRegularFile(binding) || Files.size(binding) != expected.getBytes(StandardCharsets.UTF_8).length ||
            !Files.readString(binding, StandardCharsets.UTF_8).equals(expected))
            throw new PlanningIntegrityException("full function/failure checkpoint binding differs or is missing");
    }
    private static boolean acceptedFullCheckpoint(Path record, Path failuresDirectory) throws Exception {
        if (!isAcceptedRecord(record)) return false;
        requireFullBinding(fullBindingPath(record), currentFullBinding(record, failuresDirectory.resolve(record.getFileName())));
        return true;
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

    private static void writeIfAbsentAtomic(Path target, String content, ExporterPhaseObservationOwnedV1 observation,
                                           boolean type) throws IOException {
        long since = System.nanoTime();
        boolean existing = Files.isRegularFile(target);
        ExporterPhaseObservationOwnedV1.Phase phase = type
            ? (existing ? ExporterPhaseObservationOwnedV1.Phase.TYPE_EXISTING : ExporterPhaseObservationOwnedV1.Phase.TYPE_FIRST_ATTEMPT)
            : (existing ? ExporterPhaseObservationOwnedV1.Phase.GLOBAL_EXISTING : ExporterPhaseObservationOwnedV1.Phase.GLOBAL_FIRST_ATTEMPT);
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
                    (evidenceKind.equals("globals") && (countOccurrences(record, "\n      \"byteEvidence\": {\"schemaVersion\":2,\"windows\":[") != 1 ||
                        countOccurrences(record, ",\"collectionOmissions\":[") != 1 ||
                        countOccurrences(record, "\n      \"extractionStatus\": \"recovered\",\n") != 1 ||
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

    private static ExporterSemanticFingerprintOwnedV1.BatchCommitment expectedPlanningBatch(
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
        ExporterSemanticFingerprintOwnedV1.BatchCommitment expected = semanticState.batches.get(batchIndex);
        if (expected.startIndex != startIndex || expected.endExclusive != endExclusive) {
            throw new PlanningIntegrityException("planning batch bounds differ from the authenticated semantic preflight");
        }
        return expected;
    }

    private static void requirePlanningBatchMatchesSemanticState(
        ExporterSemanticFingerprintOwnedV1.BatchCommitment expected,
        PlanningBatchValidation actual
    ) {
        ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(
            expected,
            ExporterSemanticFingerprintOwnedV1.bindAuthenticatedBatch(
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
        String prefix = "{\n  \"schemaVersion\": 4,\n  \"inputSha256\": " + json(inputSha256) + ",\n  \"functions\": [\n";
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
        long started = phaseBegin(ExporterPhaseObservationOwnedV1.Phase.PROGRESS_PUBLICATION);
        try { writeProgress(path, phase, completed, total, recovered, partial, failed, reused, currentFunction); }
        finally { phaseEnd(ExporterPhaseObservationOwnedV1.Phase.PROGRESS_PUBLICATION, started); }
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
        if (arguments.length != 4 && arguments.length != 5 && arguments.length != 6 && arguments.length != 7) {
            throw new IllegalArgumentException(
                "expected exporter SHA-256, analysis-tool SHA-256, recovery mode, output path, and supported optional arguments"
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
        if (includeDecompiledC) phaseObservation = new ExporterPhaseObservationOwnedV1();
        boolean holdFirstPlanningCheckpoint = false;
        int decompilationWorkers = 1;
        Path outputPath = Paths.get(arguments[3]).toAbsolutePath().normalize();
        Path modelAssemblyPath = outputPath;
        String optionalPolicy = null;
        if (arguments.length == 5) optionalPolicy = arguments[4];
        if (arguments.length == 7) optionalPolicy = arguments[4];
        if (arguments.length == 6 || arguments.length == 7) {
            int protocolIndex = arguments.length == 6 ? 4 : 5;
            int candidateIndex = arguments.length == 6 ? 5 : 6;
            if (!"owned-model-candidate-v1".equals(arguments[protocolIndex])) {
                throw new IllegalArgumentException("unsupported owned model candidate protocol");
            }
            modelAssemblyPath = Paths.get(arguments[candidateIndex]).toAbsolutePath().normalize();
            if (!modelAssemblyPath.getParent().equals(outputPath.getParent()) || modelAssemblyPath.equals(outputPath) ||
                !modelAssemblyPath.getFileName().toString().matches("\\.program_model\\.json-(?:model)-[0-9a-f]+-[0-9a-f]+\\.candidate")) {
                throw new IllegalArgumentException("owned program-model candidate is not a unique sibling");
            }
        }
        if (optionalPolicy != null) {
            if (!includeDecompiledC && "hold-first-planning-checkpoint-v1".equals(optionalPolicy)) {
                holdFirstPlanningCheckpoint = true;
            } else if (includeDecompiledC && optionalPolicy.matches("full-recovery-workers-v1:[1-4]")) {
                decompilationWorkers = optionalPolicy.charAt(optionalPolicy.length() - 1) - '0';
            } else {
                throw new IllegalArgumentException("unsupported export execution policy");
            }
        }
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
            byteAddress(function.getEntryPoint());
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

        collectReferencedByteEvidence(functions);
        PlanningSemanticState planningSemanticState =
            includeDecompiledC ? null : computePlanningSemanticState(functions);
        if (
            planningSemanticState != null &&
            planningSemanticState.batches.size() != planningBatchCount
        ) {
            throw new PlanningIntegrityException("semantic preflight batch count differs from its inventory");
        }
        ExporterSemanticFingerprintOwnedV1.Binding semanticBinding =
            planningSemanticState == null ? null : planningSemanticState.binding;
        String semanticState = planningSemanticState == null ? "null" :
            "{\"schemaVersion\":" + ExporterSemanticFingerprintOwnedV1.SCHEMA_VERSION +
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
        plannedTypes.clear();
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
            ExporterSemanticFingerprintOwnedV1.requireReusableState(existing, state);
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
                if (!acceptedFullCheckpoint(record, failuresDirectory)) continue;
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
            try (ExporterParallelCoordinatorOwnedV1<FunctionMetadata, FunctionExport> coordinator =
                createFullRecoveryCoordinator(decompilationWorkers)) {
                coordinator.run(functions.size(), new ExporterParallelCoordinatorOwnedV1.Source<FunctionMetadata, FunctionExport>() {
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
                        boolean accepted = acceptedFullCheckpoint(record, failuresDirectory);
                        // accepted() is visited once per index in address order, even across holes.
                        if (accepted) replayTypeCatalog(functions, index, index + 1);
                        return accepted;
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
                        ExporterPhaseObservationOwnedV1.Phase metadataPhase = retry
                            ? ExporterPhaseObservationOwnedV1.Phase.METADATA_RETRY : ExporterPhaseObservationOwnedV1.Phase.METADATA_INITIAL;
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
                        long publication = phaseBegin(ExporterPhaseObservationOwnedV1.Phase.FUNCTION_PUBLICATION);
                        try {
                            writeFunctionFailure(failuresDirectory, id, exported);
                            Path record = functionsDirectory.resolve(id + ".json");
                            writeAtomic(record, exported.record);
                            writeAtomic(fullBindingPath(record), currentFullBinding(record, failuresDirectory.resolve(id + ".json")));
                        } finally { phaseEnd(ExporterPhaseObservationOwnedV1.Phase.FUNCTION_PUBLICATION, publication); }
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
                if (!acceptedFullCheckpoint(record, failuresDirectory)) throw new IllegalStateException("missing durable function record: " + id);
                acceptedRecordStatus(record, id);
                BoundFragment functionBinding = bindCurrentFile(record, java.util.Collections.singletonList(id));
                Path failure = failuresDirectory.resolve(id + ".json");
                BoundFragment failureBinding = Files.isRegularFile(failure) ? bindCurrentFile(failure, new ArrayList<>()) : null;
                String identity = fullBinding(functionBinding.sha256, failureBinding == null ? "absent" : failureBinding.sha256);
                requireFullBinding(fullBindingPath(record), identity);
                BoundFragment identityBinding = bindCurrentFile(fullBindingPath(record), new ArrayList<>());
                if (!identityBinding.sha256.equals(sha256(identity.getBytes(StandardCharsets.UTF_8))))
                    throw new PlanningIntegrityException("full checkpoint identity changed during binding");
                functionRecords.add(functionBinding);
                if (failureBinding != null) auxiliaryEvidence.add(failureBinding);
                auxiliaryEvidence.add(identityBinding);
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
                ExporterSemanticFingerprintOwnedV1.BatchCommitment expectedBatch =
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

            // Preflight's final catalog cannot seed the prefix: that would admit future owners.
            // Rebuild only accepted batches; orphan/partial batches are prepared normally below.
            replayTypeCatalog(functions, 0, completed);
            for (int start = completed; start < total; start += PLANNING_BATCH_FUNCTIONS) {
                int end = Math.min(start + PLANNING_BATCH_FUNCTIONS, total);
                ExporterSemanticFingerprintOwnedV1.BatchCommitment expectedBatch =
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
                ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(
                    expectedBatch,
                    ExporterSemanticFingerprintOwnedV1.commitBatch(
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

        assembleModel(modelAssemblyPath, inputSha256, functionRecords, globalRecords, typeRecords, auxiliaryEvidence);
        observedProgress(progressPath, "complete", completed, total, recovered, partial, failed, reused, null);
        println(
            "program-model export complete functions=" + completed + " partial=" + partial +
                " failed=" + failed + " reused=" + reused
        );
    }
}
